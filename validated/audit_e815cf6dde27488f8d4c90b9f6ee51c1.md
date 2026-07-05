### Title
Peras Quorum Check Compares Incompatible Stake Units, Enabling Certificate Forging Bypass or Permanent Quorum Lock - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` directly compares a `PerasVoteStake` value (sourced from the ledger's absolute stake distribution) against `perasQuorumStakeThreshold` (a relative value, e.g. `3/4`), without any normalization step. The code itself documents this as an unresolved unit mismatch. Depending on how the stake distribution is populated, this either makes quorum trivially reachable by a single voter (certificate forging bypass) or permanently unreachable (Peras finality broken).

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the core Peras quorum check:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The `perasQuorumStakeThreshold` is a relative value (`3/4` by default): [2](#0-1) 

The `PerasVoteStake` values are sourced from `PerasVoteStakeDistr` via `lookupPerasVoteStake` during `validatePerasVote`, and are stored as raw `Rational` values with no enforced normalization: [3](#0-2) 

The code itself acknowledges the unit mismatch in a `TODO` comment directly on `stakeAboveThreshold`:

> *"this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."* [4](#0-3) 

And on the `PerasVoteStake` type itself:

> *"At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee."* [5](#0-4) 

The same broken comparison is used in `votesReachQuorum` (which calls `stakeAboveThreshold` on the raw sum of `vpvVoteStake` values): [6](#0-5) 

And in `updateCandidateVoteState` and `updateLoserVoteState` in the vote aggregation engine: [7](#0-6) [8](#0-7) 

The production vote ingestion path (`makePerasVotePoolWriterFromChainDB`) passes the `PerasVoteStakeDistr` directly from an STM action without any normalization: [9](#0-8) 

### Impact Explanation

Two failure modes arise from the unit mismatch:

**Mode A — Certificate forging bypass (Critical):** If the `PerasVoteStakeDistr` is populated with absolute ledger stake values (e.g., lovelace counts, or stake fractions > 1), then any voter whose absolute stake value exceeds `0.77` (= `3/4 + 2/100`) trivially satisfies the quorum check alone. A single crafted vote from such a voter causes `votesReachQuorum` to return `Just`, immediately forging a `ValidatedPerasCert` for an arbitrary block. This bypasses the quorum requirement entirely, allowing unauthorized block boosting and chain selection manipulation.

**Mode B — Permanent quorum lock (High):** If the `PerasVoteStakeDistr` is populated with very small absolute values (e.g., lovelace normalized by total lovelace in circulation, which would be on the order of `10^-15`), the sum of all votes in a round can never reach `3/4`, making Peras certificate forging permanently impossible. This breaks the Peras finality guarantee for all honest nodes.

Both modes are triggered by network-received `PerasVote` messages from unprivileged peers, processed through `processVotes` → `validatePerasVote` → `votesReachQuorum` → `stakeAboveThreshold`.

### Likelihood Explanation

The mismatch is a documented, unresolved design gap (two separate `TODO` comments in production code). The `PerasVoteStakeDistr` is populated externally and there is no type-level or runtime enforcement that values are normalized before being passed to `stakeAboveThreshold`. Any deployment that populates the stake distribution with absolute ledger stake values (the natural representation from the Cardano ledger) will trigger Mode A or Mode B depending on the magnitude of those values.

### Recommendation

`stakeAboveThreshold` must be changed to accept the total stake of the distribution and perform normalization internally before comparing against the relative threshold:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> PerasVoteStake -> Bool
stakeAboveThreshold params totalStake voteStake =
  normalizedStake >= quorumThreshold + safetyMargin
 where
  normalizedStake = unPerasVoteStake voteStake / unPerasVoteStake totalStake
  ...
```

Alternatively, enforce at the type level (phantom types or a `Normalized` newtype) that `PerasVoteStake` values passed to `stakeAboveThreshold` have already been divided by the total stake of the distribution. The `PerasVoteStakeDistr` constructor should normalize all values at construction time.

### Proof of Concept

Given `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`:

1. Peer sends a single `PerasVote` for block `B` in round `R`.
2. Node calls `validatePerasVote mkPerasParams stakeDistr vote`.
3. `lookupPerasVoteStake` returns the voter's entry from `stakeDistr`, e.g. `PerasVoteStake (1 % 1)` (absolute stake of 1 unit out of a total of, say, 1000 units — a 0.1% holder).
4. `votesReachQuorum` computes `totalVoteStake = PerasVoteStake (1 % 1)`.
5. `stakeAboveThreshold` evaluates `1 >= 3/4 + 2/100 = 0.77` → `True`.
6. A `ValidatedPerasCert` is forged for block `B` with a single vote from a 0.1% stakeholder, bypassing the intended 75%+ quorum requirement.

The inverse (Mode B) occurs when stake values are stored as lovelace fractions: a voter with 1 billion lovelace out of 45 billion ADA total has stake `≈ 2.2 × 10^-11`, and the sum of all votes across all pools still never reaches `0.77`, making certificate forging permanently impossible.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-143)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-161)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-176)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L600-606)
```haskell
updateLoserVoteState cfg vote oldState =
  assert (getPerasVoteTarget vote == ptvtTarget (ptvsVoteTally oldState)) $ do
    let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally
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
