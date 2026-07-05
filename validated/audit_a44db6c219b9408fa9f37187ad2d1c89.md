### Title
Peras Vote and Certificate Signature Verification Completely Absent in Default `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships two stub validators in the production library: `validatePerasCert` unconditionally returns `Right` (accepts every certificate with no checks), and `validatePerasVote` performs only a stake-distribution membership lookup while omitting all cryptographic signature verification. The production inbound-vote pipeline (`processVotes`) delegates entirely to `validatePerasVote`, so any unprivileged peer can inject arbitrary Peras votes — and thereby trigger certificate forging — into the node's `PerasVoteDB`/`PerasCertDB`. The forged certificates corrupt the chain-selection weight snapshot and the `getLatestCertSeen` precondition that gates all subsequent voting rounds.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:** [1](#0-0) 

The default implementation unconditionally wraps the raw certificate in `ValidatedPerasCert` and returns `Right`. No signature, no quorum proof, no round-number bounds — nothing is checked. The TODO comment explicitly acknowledges this: *"TODO: perform actual validation against all possible `PerasValidationErr` variants — see cardano-peras#120"*.

**Root cause — `validatePerasVote` skips signature verification:** [2](#0-1) 

The only check performed is `lookupPerasVoteStake vote stakeDistr` — i.e., "is this voter ID present in the public stake distribution?" No BLS signature, no VRF eligibility proof, no committee-membership proof is verified. The same TODO comment applies.

**Contrast with the real committee implementations:** The `WFALS` and `EveryoneVotes` committee modules do perform full cryptographic verification (BLS signature check, VRF output verification, seat-index bounds check): [3](#0-2) 

Those implementations are correct, but they are only reachable through the `Committee.Class` abstraction — they are **not** wired into the `BlockSupportsPeras` default instance that the production inbound pipeline uses.

**Attacker-controlled entry path — `processVotes`:** [4](#0-3) 

`processVotes` is the production handler for inbound Peras votes received from any peer over the ObjectDiffusion mini-protocol. It calls the injected `validateVote` callback, which in both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` is:

```haskell
\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote
``` [5](#0-4) [6](#0-5) 

Because `validatePerasVote` (default instance) only checks stake-distribution membership, an attacker who knows any pool ID present in the public stake distribution can craft votes for that pool ID without possessing its private key. The votes pass validation and are stored via `PerasVoteDB.addVote` / `ChainDB.addPerasVoteWithAsyncCertHandling`.

**State corruption path — certificate forging and chain-selection weight:**

Once enough crafted votes accumulate for the same target block, `implAddVote` calls `updatePerasRoundVoteStates`, which triggers `forgePerasCert` and stores the resulting certificate: [7](#0-6) 

The forged certificate is then reflected in `PerasCertDB.getWeightSnapshot`, which is used directly in chain selection to boost the boosted block's weight: [8](#0-7) 

Additionally, `getLatestCertSeen` — which is a hard precondition for voting in any round after genesis — is updated with the injected certificate: [9](#0-8) 

---

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate/vote signature validation enabling unauthorized certificate acceptance.**

An unprivileged peer can:

1. **Forge a Peras certificate for an arbitrary block** by sending enough stake-weighted votes for that block. Because `validatePerasVote` does not verify signatures, the attacker only needs to enumerate pool IDs from the public stake distribution (no private keys required).
2. **Corrupt `getWeightSnapshot`** in `PerasCertDB`, causing the honest node to assign a Peras boost to an attacker-chosen block during chain selection. This can make the node prefer a non-canonical or adversarial chain over the honest chain.
3. **Manipulate `getLatestCertSeen`**, which is a direct precondition for voting in subsequent Peras rounds. An injected certificate for a wrong block can suppress or redirect the node's own votes in future rounds.

This satisfies the allowed impact: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance"* (Critical) and *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain"* (High).

---

### Likelihood Explanation

**High.** The attack requires only:
- A network connection to the target node (standard peer connection).
- Knowledge of pool IDs present in the stake distribution — this is entirely public on-chain data.
- No private keys, no stake majority, no privileged access.

The ObjectDiffusion mini-protocol is designed to accept votes from any connected peer. The `processVotes` path is exercised for every inbound vote batch. The attacker can send a single batch of crafted votes (one per committee seat needed for quorum) and the node will accept and store them all.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` and `validatePerasVote` for every concrete `BlockSupportsPeras` instance used in production, following the pattern already established in `WFALS.implVerifyVote` and `WFALS.implVerifyCert` (BLS signature verification + VRF eligibility proof).
2. **Remove or guard the stub default implementations** so that any block type that has not yet implemented proper validation fails closed (returns `Left`) rather than open (`Right`).
3. **Track resolution of cardano-peras#120**, which is the upstream issue acknowledging this gap.

---

### Proof of Concept

```
Attacker preconditions:
  - Connected to target node as a peer via ObjectDiffusion mini-protocol.
  - Knows pool IDs P1..Pk present in the current PerasVoteStakeDistr
    (public on-chain data; no private keys needed).
  - Knows the target block B to boost (e.g., an adversarial fork tip).

Attack steps:
  1. Craft votes V1..Vk where each Vi claims:
       pvVoteRound  = current Peras round R
       pvVoteBlock  = adversarial block B
       pvVoteVoterId = Pi   (a real pool ID from the stake distribution)
     No valid BLS signature is required; the field can be zeroed or random.

  2. Send [V1..Vk] as a single batch to the target node via the
     ObjectDiffusion mini-protocol.

  3. processVotes calls validatePerasVote for each Vi.
     validatePerasVote (default instance) checks:
       lookupPerasVoteStake Vi stakeDistr  =>  Just stake_i   (succeeds)
     No signature check is performed. All votes pass.

  4. Each Vi is stored in PerasVoteDB via implAddVote.
     Once total stake >= quorum threshold, updatePerasRoundVoteStates
     triggers forgePerasCert, producing a ValidatedPerasCert for block B.

  5. The certificate is stored in PerasCertDB.
     getWeightSnapshot now includes a Peras boost for block B.
     getLatestCertSeen now returns this certificate.

  6. Chain selection on the honest node now prefers block B (or any chain
     extending B) over the honest chain, because B carries a Peras boost.
     Future voting rounds are also anchored to this injected certificate.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L327-392)
```haskell
implVerifyVote ::
  forall crypto.
  ( CryptoSupportsVoteSigning crypto
  , CryptoSupportsVRF crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Vote crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (EligibilityWitness crypto WFALS)
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
        let numSeats =
              localSortitionNumSeats
                (nonPersistentCommitteeSize committee)
                (totalNonPersistentStake committee)
                voterStake
                (normalizeVRFOutput vrfOutput)
        case nonZero numSeats of
          Nothing ->
            Left (ZeroNonPersistentSeats seatIndex)
          Just nonZeroNumSeats ->
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-113)
```haskell
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-246)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr

    pure
      ( addPerasVoteRes
      , PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvsLastTicketNo'
          }
      )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-71)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
```
