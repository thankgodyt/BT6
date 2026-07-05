### Title
Peras Vote and Certificate Signature Verification Completely Absent in Production Network Path — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used in the live Peras object-diffusion miniprotocol path omits all cryptographic verification for both votes and certificates. `validatePerasVote` accepts any vote whose claimed voter ID appears in the stake distribution, with no signature check, because the `PerasVote` data type in this instance carries no signature field at all. `validatePerasCert` unconditionally returns `Right` for every certificate it receives. An unprivileged peer can therefore impersonate any stake pool, inject fraudulent votes, trigger quorum, and cause the node to forge and accept a `ValidatedPerasCert` for an attacker-chosen block — directly manipulating Peras-boosted chain selection.

---

### Finding Description

**Degenerate instance — no signature field, no cryptographic check**

The `PerasVote` data type defined inside the degenerate `BlockSupportsPeras` instance carries only three fields:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

There is no signature field. [1](#0-0) 

`validatePerasVote` therefore can only check whether the claimed voter ID has stake in the distribution. It performs no cryptographic proof that the vote was cast by the actual key holder:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`validatePerasCert` is even weaker — it unconditionally accepts every certificate:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [3](#0-2) 

Both functions are explicitly marked TODO and the instance is labelled "degenerate": [4](#0-3) 

**This degenerate instance is wired into the live network processing path**

`makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB` both call `validatePerasVote mkPerasParams sd vote` — resolving to the degenerate instance above — before adding votes to the `PerasVoteDB`: [5](#0-4) [6](#0-5) 

`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` both call `validatePerasCert mkPerasParams` — the unconditional `Right` — before adding certificates: [7](#0-6) [8](#0-7) 

`processVotes` and `processCerts` are the inbound handlers for the Peras object-diffusion miniprotocol. They call the validator and, on success, persist the object and trigger downstream chain-selection side-effects: [9](#0-8) [10](#0-9) 

**Quorum and certificate forging are triggered by the fraudulent votes**

Once fraudulent `ValidatedPerasVote` objects accumulate enough stake, `updateCandidateVoteState` calls `forgePerasCert` and produces a `ValidatedPerasCert` for the attacker-chosen block. The degenerate `forgePerasCert` always succeeds: [11](#0-10) [12](#0-11) 

---

### Impact Explanation

**Severity: Critical — Bypass of Peras vote/certificate authorization enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer can:

1. Craft `PerasVote` messages claiming to be from any high-stake pool ID visible in the public stake distribution, voting for an attacker-chosen block.
2. Pass `validatePerasVote` (stake-presence check only, no signature) and be stored as `ValidatedPerasVote` objects.
3. Accumulate enough fraudulent stake to trigger `forgePerasCert`, producing a `ValidatedPerasCert` for the attacker's block.
4. Alternatively, send a single crafted `PerasCert` that passes `validatePerasCert` unconditionally, directly injecting a certificate for any block.

The resulting `ValidatedPerasCert` is used by the Peras chain-selection logic to boost the certified block. This lets an adversary make an honest node prefer a non-canonical or adversarially-chosen chain, breaking chain-selection safety.

---

### Likelihood Explanation

**Medium-High.** The attack requires only a network connection to a Peras-enabled node and knowledge of the public stake distribution (which is on-chain). No keys, no stake, no admin access are needed. The `PerasVote` wire format is serialised/deserialised over the object-diffusion miniprotocol and any peer can send arbitrary vote messages. The only barrier is that the Peras feature must be active on the network.

---

### Recommendation

1. **Votes**: Add a cryptographic signature field to `PerasVote` (analogous to the `sig` field in `WFALSPersistentVote`/`EveryoneVotesVote`). Implement `validatePerasVote` to verify the signature against the voter's registered VRF/KES key before accepting the vote.

2. **Certificates**: Implement `validatePerasCert` to verify the aggregate BLS signature (as done in `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert`) rather than unconditionally returning `Right`.

3. **Tracking**: Replace the degenerate `instance StandardHash blk => BlockSupportsPeras blk` with a proper per-era instance that wires in the real committee crypto, mirroring the `WFALS`/`EveryoneVotes` committee implementations already present in the codebase. [13](#0-12) [14](#0-13) 

---

### Proof of Concept

**Vote impersonation leading to fraudulent quorum:**

```
Attacker (unprivileged peer) connects via Peras object-diffusion miniprotocol.

1. Attacker reads the public stake distribution to find voter IDs with large stake.

2. Attacker sends a batch of PerasVote messages:
     PerasVote { pvVoteRound  = <current round>
               , pvVoteBlock  = <attacker-chosen block hash>
               , pvVoteVoterId = <high-stake pool ID> }
   (No signature required — the type has no signature field.)

3. processVotes calls:
     validatePerasVote mkPerasParams stakeDistr vote
   which resolves to the degenerate instance:
     | Just stake <- lookupPerasVoteStake vote stakeDistr = Right (ValidatedPerasVote ...)
   => vote accepted.

4. implAddVote stores the vote and calls updatePerasRoundVoteStates.

5. Once accumulated fraudulent stake exceeds the quorum threshold,
   updateCandidateVoteState calls forgePerasCert (degenerate: always Right),
   producing ValidatedPerasCert { vpcCert = PerasCert { pcCertRound = <round>
                                                       , pcCertBoostedBlock = <attacker block> }
                                 , vpcCertBoost = perasWeight params }.

6. The certificate is stored in PerasCertDB and used by chain selection
   to boost the attacker-chosen block.
```

**Direct certificate injection (even simpler):**

```
Attacker sends a single PerasCert { pcCertRound = <round>, pcCertBoostedBlock = <attacker block> }.

processCerts calls validatePerasCert mkPerasParams cert
  => degenerate instance: always Right.

Certificate is stored and boosts the attacker's block unconditionally.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L376-385)
```haskell
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-112)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-180)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L327-370)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-586)
```haskell
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
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
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)

    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig

    -- Verify VRF outputs for non-persistent voters (if any)
    case catMaybes (NonEmpty.toList optionalVRFKeysAndOutputs) of
      -- No non-persistent voters => no VRF outputs to verify
      [] -> do
        pure ()
      -- Some non-persistent voters => verify their aggregate VRF outputs
      vrfKeysAndOutputs -> do
        let (vrfVerificationKeys, vrfOutputs) =
              munzip
                . NonEmpty.fromList -- safe 'vrfKeysAndOutputs' /= []
                $ vrfKeysAndOutputs
        bimap InvalidCertSignature id $
          batchVerifyVRFOutputs
            vrfVerificationKeys
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
            vrfOutputs

    -- Return the list of voters attesting the election winner
    pure members
```
