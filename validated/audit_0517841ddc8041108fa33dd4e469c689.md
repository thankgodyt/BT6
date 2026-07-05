### Title
Peras Certificate and Vote Validation Bypass: No Cryptographic Verification in Default `BlockSupportsPeras` Instance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance used for all block types provides stub implementations of `validatePerasCert` and `validatePerasVote` that perform no cryptographic signature verification. `validatePerasCert` unconditionally returns `Right` (accepting every certificate), and `validatePerasVote` only checks that the voter ID exists in the stake distribution without verifying the BLS vote signature. Both stubs are wired into the production inbound-object-diffusion path. An unprivileged peer can inject fabricated Peras certificates or votes with valid voter IDs but tampered content, bypassing all cryptographic checks.

---

### Finding Description

The `BlockSupportsPeras` type class declares two validation methods:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk ->
  PerasVoteStakeDistr ->
  PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The default instance (applied to all `StandardHash blk` block types) implements them as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`validatePerasCert` performs **zero** checks — it wraps any incoming certificate in `Right` unconditionally. `validatePerasVote` only calls `lookupPerasVoteStake` (a `Map.lookup` on `pvVoteVoterId`) and never touches `pvSignature`, `pvRoundNo`, or `pvBoostedBlock`. [3](#0-2) 

These stubs are wired directly into the production inbound vote-diffusion path. `makePerasVotePoolWriterFromChainDB` — the function used by the node kernel to process votes received from peers — calls `validatePerasVote` as its sole validation gate before adding votes to the `ChainDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

The `processVotes` function that drives this path accepts any vote that passes `validateVote` and adds it to the pool: [5](#0-4) 

The `PerasVote.V1` type carries a `pvSignature :: VoteSignature PerasBLSCrypto` field that is a BLS signature over `(pvRoundNo, pvBoostedBlock)`. Neither field nor the signature is ever checked by the default `validatePerasVote`. [6](#0-5) 

The correct cryptographic verification logic exists in `implVerifyVote` (WFALS) and `implVerifyCert` (WFALS/EveryoneVotes), which call `verifyVoteSignature` and `verifyAggregateVoteSignature` respectively, but these are only reachable through the `CryptoSupportsVotingCommittee` interface — not through the `BlockSupportsPeras` default instance used in the production diffusion path. [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**`validatePerasCert` (Critical — unauthorized certificate acceptance):** Because the function unconditionally returns `Right`, any peer can craft a `PerasCert` with an arbitrary `pcRoundNo` and `pcBoostedBlock` (pointing to any block hash), and the receiving node will accept it as a `ValidatedPerasCert` with full boost weight. A Peras certificate boosts a block's weight in chain selection. Accepting a fabricated certificate causes the honest node to assign unearned boost weight to an attacker-chosen block, making the node prefer a non-canonical chain. This is a bypass of Peras certificate checks enabling unauthorized certificate acceptance, matching the Critical impact scope.

**`validatePerasVote` (Critical — unauthorized vote acceptance / aggregate signature poisoning):** A malicious peer with a known-valid voter ID (any pool operator in the stake distribution) can send a `PerasVote` with a valid `pvVoteVoterId` but a tampered `pvBoostedBlock`, `pvRoundNo`, or `pvSignature`. The vote passes `validatePerasVote` and enters the pool. When the node attempts to aggregate votes into a certificate via `implForgeCert`, the BLS aggregate signature is computed over the individual signatures. Because the tampered vote's signature was computed over different content than the honest votes, the resulting aggregate signature is invalid and will be rejected by `verifyAggregateVoteSignature` at certificate verification time. This prevents quorum from being reached for the targeted round, blocking Peras boosting for that round. Since signing requests are matched deterministically against quadruples/rounds, a single malicious pool operator can persistently block boosting for targeted rounds.

---

### Likelihood Explanation

The attack requires only that the adversary control a pool operator key that appears in the current epoch's stake distribution — a low bar for any registered stake pool. The inbound diffusion path (`makePerasVotePoolWriterFromChainDB` → `processVotes` → `validatePerasVote`) is reachable by any connected peer sending a crafted vote object over the Peras vote mini-protocol. No special privileges, key compromise, or stake majority is required. The stub implementations are in the production source tree and are the active code path for all block types.

---

### Recommendation

**Short term:** Replace the stub `validatePerasCert` and `validatePerasVote` implementations in the default `BlockSupportsPeras` instance with calls to the cryptographic verification logic already present in `implVerifyCert` and `implVerifyVote` (in `Ouroboros.Consensus.Committee.WFALS` and `Ouroboros.Consensus.Committee.EveryoneVotes`). At minimum, `validatePerasCert` must never return `Right` without verifying the aggregate BLS signature against `(pcRoundNo, pcBoostedBlock)`.

**Long term:** The `BlockSupportsPeras` class documentation should explicitly state that `validatePerasCert` and `validatePerasVote` are security-critical entry points and that any instance must perform full cryptographic verification before returning `Right`. The TODO at `https://github.com/tweag/cardano-peras/issues/120` should be treated as a security-blocking issue.

---

### Proof of Concept

1. Attacker controls pool `P` with a valid entry in `PerasVoteStakeDistr`.
2. Attacker observes a Peras election for round `R` targeting block `B`.
3. Attacker constructs a `PerasVote` with `pvVoteVoterId = P`, `pvRoundNo = R`, `pvBoostedBlock = B'` (a different block hash), and `pvSignature` = a BLS signature over `(R, B')` using `P`'s key.
4. Attacker sends this vote to an honest node via the Peras vote mini-protocol.
5. `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote`.
6. `lookupPerasVoteStake` finds `P` in the distribution and returns `Just stake`.
7. The vote is accepted as `ValidatedPerasVote` and added to the pool — no BLS signature check occurs.
8. When the node aggregates votes for round `R`, `implForgeCert` calls `aggregateVoteSignatures` over all collected signatures, including the attacker's signature over `(R, B')` mixed with honest signatures over `(R, B)`.
9. The resulting aggregate signature is invalid; `verifyAggregateVoteSignature` rejects it.
10. No certificate is forged for round `R`; Peras boosting for that round is blocked.

For the `validatePerasCert` path: attacker constructs a `PerasCert` with `pcRoundNo = R`, `pcBoostedBlock = B'` (attacker-chosen block), and a garbage `pcSignature`. The node calls `validatePerasCert` which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally. The fabricated certificate is accepted and used to boost block `B'` in chain selection. [9](#0-8) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-562)
```haskell
-- | Verify a certificate attesting the winner of a given election
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
```
