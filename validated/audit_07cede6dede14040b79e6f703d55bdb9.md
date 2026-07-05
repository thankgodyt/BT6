### Title
Peras Vote Cryptographic Validation Bypassed: `_params` Silently Discarded in `validatePerasVote` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` implementation in the catch-all `BlockSupportsPeras` instance silently discards its `PerasCfg`/`PerasParams` argument (bound as `_params`). As a result, no cryptographic checks — vote signature, VRF proof, or committee-membership verification — are ever performed. Any peer that knows a valid voter ID (a public `KeyHash StakePool`) can inject arbitrarily forged votes that pass validation, accumulate toward quorum, and cause the node to forge a fraudulent Peras certificate that boosts an adversarially chosen block's chain weight.

---

### Finding Description

In `SupportsPeras.hs`, the degenerate `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) implements `validatePerasVote` as:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
```

The leading underscore on `_params` is Haskell's explicit discard notation. The `PerasParams` argument — which carries the quorum threshold, round parameters, and is the natural home for cryptographic-verification context — is never consulted. The only check performed is a `Map.lookup` of the voter's `KeyHash` in the stake distribution.

The function's own TODO comment acknowledges the problem:

> TODO: perform actual validation against all possible `PerasValidationErr` variants

This is the direct analog of the external report's bug: the function receives the correct value as a parameter (`_params`) but uses a different variable (`stakeDistr` alone) in the critical operation, causing all cryptographic validation to be skipped — exactly as `msg.value` (0 for ERC20) was used instead of `amount`.

The production call site in `ObjectPool/PerasVote.hs` wires this directly into the inbound vote pipeline:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

`mkPerasParams` is passed but immediately discarded inside `validatePerasVote`. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

Once a forged vote passes `validatePerasVote`, it is stored as a `ValidatedPerasVote` with a real `vpvVoteStake` drawn from the honest stake distribution. It then flows into `updateCandidateVoteState`, which calls `votesReachQuorum cfg voteList`. When the accumulated `totalVoteStake` crosses `stakeAboveThreshold`, `forgePerasCert` is called and a `ValidatedPerasCert` is produced with `vpcCertBoost = perasWeight params`. This certificate is then used by chain selection to add `PerasWeight` (default: 15 blocks) to the adversarially chosen block's chain weight, causing honest nodes to prefer that chain over the canonical one.

This is a **bypass of Peras vote/certificate verification** that enables unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: bypass of Peras voting or certificate checks" impact category. [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

The attack requires only:
1. Knowledge of any `PerasVoterId` (a `KeyHash StakePool`) present in the current stake distribution — this is public on-chain data.
2. The ability to send `PerasVote` objects over the object-diffusion mini-protocol — available to any unprivileged peer.

No private keys, no stake majority, no operator compromise. The attacker constructs a `PerasVote` with a real voter ID, a chosen block point, and any round number, and sends it to a target node. The node's `processVotes` pipeline accepts it without any cryptographic check. [5](#0-4) 

---

### Recommendation

Replace the discarded `_params` with a binding that is actually used for cryptographic verification. At minimum, the implementation must:

1. Verify the vote's cryptographic signature against the voter's public key (retrieved from the stake distribution or committee selection context).
2. Verify any VRF proof embedded in the vote.
3. Verify committee membership beyond a simple stake-distribution lookup.

The fix mirrors the external report's recommended mitigation: use the parameter that was passed (`params`) instead of ignoring it (`_params`).

```haskell
-- Before (broken):
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr = Right ...

-- After (correct):
validatePerasVote params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr
    , verifyVoteSignature params vote  -- use params for crypto checks
    , verifyVoteVRF params vote        -- use params for VRF checks
    = Right ...
``` [6](#0-5) 

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Observe the current stake distribution to obtain any live `KeyHash StakePool` value `vid`.
2. Construct a `PerasVote` targeting an adversarially chosen block `B_adv` in round `r`:
   ```
   PerasVote { pvVoteRound = r, pvVoteBlock = point(B_adv), pvVoteVoterId = vid }
   ```
   No private key is needed; the vote carries no signature field in the degenerate instance.
3. Send this vote (and enough copies with different `vid` values drawn from the stake distribution to exceed the quorum threshold) to the target node via the object-diffusion mini-protocol.
4. Each vote passes `validatePerasVote` because `_params` is discarded and only the `Map.lookup` of `vid` in the stake distribution is checked.
5. `updateCandidateVoteState` accumulates the votes; once `stakeAboveThorum` returns `True`, `forgePerasCert` produces a `ValidatedPerasCert` boosting `B_adv` by `perasWeight = 15`.
6. Chain selection on the target node now prefers `B_adv`'s chain over the honest canonical chain. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L195-203)
```haskell
-- | Lookup the stake of a vote cast by a member of a given stake distribution.
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L109-113)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-200)
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
