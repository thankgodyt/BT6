### Title
Peras Quorum Check Compares Accumulated Vote Stake Against Normalized Threshold Without Normalization, Enabling Incorrect Certificate Forging — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares the raw accumulated `PerasVoteStake` (a sum of individual vote stakes) directly against the `perasQuorumStakeThreshold` (a normalized relative value, e.g., `3/4`), without performing normalization. The function's own TODO comment explicitly acknowledges this unit mismatch. This is the direct analog of the EIP-2981 bug: just as the NFT market always passes the constant `BASIS_POINTS` (10,000) instead of the actual `_salePrice`, the Peras quorum check always uses the raw accumulated stake instead of the normalized fraction of total committee stake, causing the threshold comparison to be incorrect.

---

### Finding Description

`stakeAboveThreshold` is defined at line 162 of `SupportsPeras.hs`:

```haskell
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
``` [1](#0-0) 

The `perasQuorumStakeThreshold` is a normalized relative value (e.g., `3/4`):

```haskell
perasQuorumStakeThreshold =
    PerasQuorumStakeThreshold (3 / 4)
``` [2](#0-1) 

The `PerasVoteStake` passed to `stakeAboveThreshold` is `ptvtTotalStake`, which is accumulated by summing raw `vpvVoteStake` values from individual votes:

```haskell
ptvtTotalStake = ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote)
``` [3](#0-2) 

This accumulated sum is then compared against the normalized threshold in two critical call sites:

1. **`updateLoserVoteState`** — checks whether a losing target has gone above quorum (an error condition):

```haskell
let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
``` [4](#0-3) 

2. **`updateCandidateVoteState`** — checks whether a candidate has reached quorum and should have a certificate forged:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [5](#0-4) 

The `PerasVoteStake` type's own documentation acknowledges the ambiguity:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [6](#0-5) 

The unit mismatch has two failure modes, directly mirroring the EIP-2981 bug's two failure modes:

- **Failure mode 1 (analog to "recipients with < 1 BPS receive zero royalties"):** If individual `PerasVoteStake` values are small normalized fractions (e.g., each voter holds 0.1% of total stake), their sum across many votes may never reach `3/4`, so quorum is never detected even when the full honest committee has voted. Certificates are never forged, Peras boosts never apply, and the protocol degrades silently.

- **Failure mode 2 (analog to "total royalties cut scaled up to 10%"):** If `PerasVoteStake` values are absolute (not normalized), a small number of high-stake voters could cause the accumulated sum to exceed `3/4` prematurely, forging a certificate before actual quorum is reached. This is the more dangerous direction.

---

### Impact Explanation

Peras certificates directly control chain weight via `PerasWeight` boosts. The `wsvTotalWeight` used in chain selection is:

```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
``` [7](#0-6) 

A falsely forged certificate (quorum not actually reached) boosts a block's chain weight, causing honest nodes to prefer a non-canonical chain over the canonical one. This is a **High** chain-selection bug: an unprivileged peer diffusing crafted votes can trigger false quorum detection, causing honest nodes to switch to an adversarially boosted chain without the required honest-stake backing.

---

### Likelihood Explanation

The TODO comment is present in production code and explicitly states the normalization is not enforced. The `mkPerasParams` default sets `perasQuorumStakeThreshold = 3/4`, a normalized value. Any deployment where `PerasVoteStake` values are not pre-normalized before being passed to `stakeAboveThreshold` (which the TODO says is not guaranteed) will exhibit incorrect quorum detection on every vote aggregation. The entry path is the vote diffusion miniprotocol, reachable by any unprivileged peer.

---

### Recommendation

1. Modify `stakeAboveThreshold` to accept the total committee stake distribution and perform normalization internally before comparing against the threshold, eliminating the unit ambiguity at the call site.
2. Alternatively, enforce that `PerasVoteStake` values stored in `PerasVoteStakeDistr` are always pre-normalized (expressed as fractions of total committee stake) before being summed into `ptvtTotalStake`, and document this invariant with a type-level or runtime assertion.
3. Add a property-based test that verifies: if all honest committee members vote for the same block, quorum is detected if and only if their combined normalized stake exceeds `perasQuorumStakeThreshold`.

---

### Proof of Concept

Consider a Peras deployment with `perasQuorumStakeThreshold = 3/4` and a committee where each of 10 voters holds 10% of total stake (absolute stake = 0.1 each, normalized = 0.1).

**Scenario A (absolute stakes, false positive):** If `PerasVoteStake` values are stored as absolute lovelace fractions (e.g., `0.1` each), then after 8 votes the accumulated `ptvtTotalStake = 0.8 >= 0.75`, triggering `stakeAboveThreshold = True` and forging a certificate. But only 80% of the committee voted — if the quorum threshold is meant to require 75% of *total ledger stake* (not committee stake), this is a false positive.

**Scenario B (normalized stakes, false negative):** If `PerasVoteStake` values are normalized per-committee-member (e.g., `1/10` each), then after all 10 votes the accumulated `ptvtTotalStake = 1.0 >= 0.75`, which is correct. But if the normalization is done differently (e.g., per total ledger stake where each voter has 0.001), the sum never reaches `0.75`, quorum is never detected, and no certificate is ever forged — silently disabling Peras boosts.

In both cases, the root cause is the same as the EIP-2981 bug: the comparison uses a value in the wrong units relative to the threshold, because normalization is not enforced at the comparison site. [1](#0-0) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L453-459)
```haskell
    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-606)
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

-- | Add a vote to an existing target vote state if it isn't already present.
--
-- PRECONDITION: the vote's target must match the underlying tally's target.
--
-- May fail if the loser goes above quorum by adding the vote.
updateLoserVoteState ::
  StandardHash blk =>
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Loser ->
  Either (PerasTargetVoteState blk 'Loser) (PerasTargetVoteState blk 'Loser)
updateLoserVoteState cfg vote oldState =
  assert (getPerasVoteTarget vote == ptvtTarget (ptvsVoteTally oldState)) $ do
    let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-60)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
```
