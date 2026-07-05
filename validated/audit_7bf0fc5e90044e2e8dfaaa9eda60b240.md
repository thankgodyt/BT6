### Title
Degenerate `BlockSupportsPeras` Instance Skips All Vote and Certificate Cryptographic Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The only production `BlockSupportsPeras` instance unconditionally accepts any Peras vote from any voter ID present in the stake distribution (no signature check, no VRF eligibility check) and unconditionally accepts any Peras certificate (no aggregate-signature check). An unprivileged peer can impersonate any eligible voter, accumulate enough fake votes to reach quorum, and cause honest nodes to forge and accept a Peras certificate for an adversarially chosen block, boosting that block's chain weight.

---

### Finding Description

The `BlockSupportsPeras` type class defines two critical validation entry points: `validatePerasVote` and `validatePerasCert`. The only concrete instance in the codebase is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` that is explicitly labelled "degenerate" in a TODO comment.

`validatePerasCert` unconditionally returns `Right`:

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

`validatePerasVote` only checks that the voter ID exists in the stake distribution map — it performs **no signature verification, no VRF eligibility check, and ignores `_params` entirely**:

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

This is the wrong implementation of the vote validation function — analogous to the external report's wrong `getLockedAmount()` — because it omits the core security invariant (cryptographic proof of voter identity and eligibility) while still producing a `ValidatedPerasVote` that is trusted by all downstream quorum logic.

The `processVotes` inbound handler in `ObjectPool/PerasVote.hs` calls `validatePerasVote` on every network-received vote and, if validation passes, adds the vote to the `PerasVoteDB`. The `updateTargetVoteTally` / `votesReachQuorum` / `updateCandidateVoteState` pipeline then accumulates stake and forges a certificate the moment the quorum threshold is crossed.

There is also a compounding unit-mismatch acknowledged by a TODO in `stakeAboveThreshold`:

```
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values.
```

If the `PerasVoteStakeDistr` supplied at runtime contains absolute (un-normalized) stake values while `perasQuorumStakeThreshold` is a relative value (default `3/4`), a single voter whose absolute stake exceeds `0.77` would alone satisfy quorum — directly mirroring the external report's N×amount over-locking pattern.

---

### Impact Explanation

An adversary who can send Peras vote messages (any unprivileged peer connected via the miniprotocol) can:

1. Craft `PerasVote` messages claiming to be any voter ID present in the `PerasVoteStakeDistr`.
2. Because `validatePerasVote` only checks map membership, all such votes pass validation.
3. Accumulate enough fake votes to exceed `perasQuorumStakeThreshold + safetyMargin`.
4. Trigger `votesReachQuorum → forgePerasCert`, producing a `ValidatedPerasCert` for an adversarially chosen block.
5. The certificate boosts that block's chain weight by `perasWeight = 15`, causing honest nodes to prefer the adversary's chain over the honest chain.

This is a **bypass of Peras voting and certificate checks** enabling unauthorized certificate acceptance and chain-selection manipulation — matching the Critical impact category.

---

### Likelihood Explanation

The entry path is fully reachable by any peer connected to the node's miniprotocol layer. The `PerasVoteStakeDistr` is derived from the public ledger state, so all eligible voter IDs are publicly known. No key material, admin access, or stake majority is required. The only prerequisite is a network connection to a target node.

---

### Recommendation

1. **Implement real vote validation** in `validatePerasVote`: verify the vote signature against the voter's registered verification key and verify VRF eligibility before accepting a vote as `ValidatedPerasVote`.
2. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate BLS signature over all claimed voter keys and verify each voter's VRF output grants committee membership.
3. **Resolve the unit mismatch** in `stakeAboveThreshold`: either normalize `PerasVoteStake` values to sum to 1 before comparison, or change the function to accept the total stake and compute the ratio internally.
4. Remove the degenerate catch-all `instance StandardHash blk => BlockSupportsPeras blk` once concrete era-specific instances with full validation are in place.

---

### Proof of Concept

**Setup**: Node running with default `mkPerasParams` (`perasQuorumStakeThreshold = 3/4`, `perasWeight = 15`). Ledger stake distribution has 10 pools each with 10% stake.

**Attack**:
1. Attacker connects to the node via the Peras vote miniprotocol.
2. Attacker sends 8 `PerasVote` messages, each claiming a different pool ID from the public stake distribution, all voting for the same adversarial block `B_adv` in round `R`.
3. Each vote passes `validatePerasVote` (pool ID found in map, no signature checked).
4. After the 8th vote, `ptvtTotalStake = 0.8 > 0.75 + 0.02 = 0.77`, so `stakeAboveThreshold` returns `True`.
5. `updateCandidateVoteState` calls `votesReachQuorum` → `forgePerasCert` → `ValidatedPerasCert` for `B_adv` is stored.
6. `B_adv` receives a boost of `+15` in chain weight; honest nodes running chain selection prefer it over the honest tip. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-272)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L566-587)
```haskell
-- | Add a vote to an existing target vote state if it isn't already present.
--
-- May fail if the candidate is elected winner but forging the certificate fails.
updateCandidateVoteState ::
  StandardHash blk =>
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
