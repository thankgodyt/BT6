### Title
Missing Cryptographic Signature Verification in `validatePerasVote` Allows Unauthorized Peras Vote Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function in `BlockSupportsPeras` is a stub implementation that only checks whether a voter's ID exists in the stake distribution, but performs no cryptographic signature verification. Any unprivileged peer that knows the public stake distribution (which is public on-chain data) can submit forged votes on behalf of any registered pool. If enough forged votes are submitted, the node's internal quorum logic will generate a fake Peras certificate, which is then used to boost a non-canonical block in chain selection.

---

### Finding Description

**Root cause:** `validatePerasVote` is an acknowledged stub (marked with a `TODO` referencing issue `#120`) that omits all cryptographic checks. It accepts a vote as `ValidatedPerasVote` solely on the basis that the `pvVoteVoterId` field maps to an entry in the `PerasVoteStakeDistr`:

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
``` [1](#0-0) 

The function ignores `_params` entirely and performs no VRF proof check, no KES/BLS signature check, and no eligibility proof check. The `PerasValidationErr` data type is itself a single-constructor stub with no fields, confirming no real error discrimination is possible:

```haskell
data PerasValidationErr blk
  = PerasValidationErr
  deriving stock (Show, Eq)
``` [2](#0-1) 

**Contrast with the correct implementation:** The `WFALS` and `EveryoneVotes` committee implementations in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs` do perform full cryptographic verification — checking vote signatures, VRF proofs, and seat eligibility — before returning an `EligibilityWitness`. The `BlockSupportsPeras` stub bypasses all of this. [3](#0-2) 

**Attack path:**

1. Attacker reads the public `PerasVoteStakeDistr` (on-chain, public).
2. Attacker crafts a `PerasVote` with `pvVoteVoterId` set to any pool ID present in the distribution, targeting a chosen block.
3. Attacker submits the vote via the Peras mini-protocol handler.
4. The node calls `validatePerasVote`, which returns `Right ValidatedPerasVote` because the pool ID is found in the distribution — no signature is checked.
5. The `ValidatedPerasVote` is passed to `PerasVoteDB.addVote` → `implAddVote` → `updatePerasRoundVoteStates`.
6. The attacker repeats for enough pool IDs to accumulate stake above the quorum threshold (`perasQuorumStakeThreshold`, currently `3/4`).
7. `votesReachQuorum` returns `Just`, `forgePerasCert` is called, and a `ValidatedPerasCert` is stored in the `PerasVoteDB`.
8. The certificate's `vpcCertBoost` (currently `perasWeight = 15`) is applied to the attacker-chosen block in `preferAnchoredCandidate` / `chainSelectionForBlock`, causing the node to prefer that block over the honest canonical chain. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Severity: Critical.** This is a direct bypass of Peras voting/certificate checks. An unprivileged peer with knowledge of the public stake distribution can forge votes for any registered pool without possessing their private keys. By submitting enough forged votes, the attacker can manufacture a quorum certificate for an arbitrary block. The resulting `ValidatedPerasCert` is used in chain selection to boost that block's weight by `perasWeight` (15 blocks), causing an honest node to prefer a non-canonical or adversarially-chosen chain. This undermines the core Peras safety guarantee — that a boosted block has been honestly certified by a quorum of stake.

---

### Likelihood Explanation

**High.** The stake distribution is public on-chain data. No private key material, operator access, or stake majority is required. The attacker only needs to send crafted vote messages over the Peras mini-protocol. The stub is in production source (`src/ouroboros-consensus/`), not a test file, and is the active implementation dispatched by the `BlockSupportsPeras` typeclass. The TODO comment and linked issue confirm this is a known incomplete implementation, not an intentional design.

---

### Recommendation

Replace the stub `validatePerasVote` with a full implementation that:
1. Verifies the cryptographic vote signature against the pool's registered public key.
2. Verifies any VRF eligibility proof (for non-persistent committee members).
3. Checks that the vote's round and target are within the valid window.

This mirrors the complete verification already implemented in `implVerifyVote` for `WFALS` and `EveryoneVotes`. [6](#0-5) 

---

### Proof of Concept

```
1. Observe the current epoch's PerasVoteStakeDistr (public ledger state).
2. Pick any PerasRoundNo R and a target block B (e.g., a fork tip).
3. For each pool P_i in the distribution with stake s_i:
     Craft PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = P_i }
     Submit to the node's Peras vote ingestion endpoint.
4. validatePerasVote accepts each vote (pool ID found in distribution).
5. After submitting votes totalling stake > 3/4 + 2/100 of total:
     votesReachQuorum returns Just, forgePerasCert produces ValidatedPerasCert for B.
6. chainSelectionForBlock now sees B with boost weight +15, preferring it over the
   honest canonical tip.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L340-343)
```haskell
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-392)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-198)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L571-587)
```haskell
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Candidate ->
  Either
    (PerasForgeErr blk)
    (PerasVoteStateCandidateOrWinner blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L202-232)
```haskell
-- | Verify a vote cast by a committee member in a given election
implVerifyVote ::
  forall crypto.
  CryptoSupportsVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Vote crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (EligibilityWitness crypto EveryoneVotes)
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```
