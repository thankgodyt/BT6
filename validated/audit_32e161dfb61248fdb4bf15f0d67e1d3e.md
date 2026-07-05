### Title
Peras Quorum Check Unit Mismatch Enables Certificate Forging with Insufficient Stake — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares the accumulated `PerasVoteStake` (a sum of per-voter values drawn directly from `PerasVoteStakeDistr`) against a relative quorum threshold without first normalizing the stake values. The function itself carries an explicit TODO acknowledging this unit mismatch. If `PerasVoteStakeDistr` is populated with absolute ledger-stake values (as the ledger naturally provides), the comparison is dimensionally incorrect: any positive absolute stake trivially exceeds a fractional threshold, allowing a single vote to forge a certificate.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `stake = unPerasVoteStake voteStake` is the raw accumulated `Rational` and `quorumThreshold` is `unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)` — a relative fraction (e.g. `0.75`).

The function's own documentation states:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

No normalization is performed anywhere in the call chain. `PerasVoteStake` values are assigned in `validatePerasVote` by a direct lookup from `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
```

These raw values are then summed in `updateTargetVoteTally`:

```haskell
(votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
```

and the sum is passed directly to `stakeAboveThreshold` in both `votesReachQuorum` (called from `updateCandidateVoteState`) and `updateLoserVoteState`:

```haskell
aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
```

This is the exact analog of the external report's pattern: two correlated quantities — accumulated vote stake and the quorum threshold — are compared without ensuring they share the same unit, skewing the effective ratio and breaking the authorization invariant.

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated from the ledger's absolute stake distribution (e.g. lovelace values), then `ptvtTotalStake` after even a single vote will be a large integer (e.g. `1_000_000`), while `quorumThreshold` is a fraction such as `0.75`. The comparison `1_000_000 >= 0.75` is always `True`.

Consequences:
1. **Unauthorized certificate forging**: Any committee member can forge a Peras certificate for an arbitrary block with a single vote, regardless of their actual fractional stake.
2. **Chain selection manipulation**: The forged certificate is added to the `PerasCertDB` and its `vpcCertBoost` is incorporated into the `PerasWeightSnapshot`. `weightedSelectView` then computes `wsvTotalWeight = wsvBlockNo + wsvWeightBoost`, causing `preferAnchoredCandidate` to prefer the adversarially boosted chain over the honest chain.
3. **Secondary crash**: Any subsequent vote for a different target in the same round triggers `RoundVoteStateLoserAboveQuorum` → `MultipleWinnersInRound` exception, because the loser's stake also trivially exceeds the threshold.

This matches the **High** impact category: a chain-selection bug that lets an unprivileged peer (any committee member) make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The code explicitly flags the missing normalization with a TODO comment at the call site. The `PerasVoteStakeDistr` is sourced from `getStakeDistrSTM`, which in production would be derived from the ledger's stake distribution — an absolute-value map. The comment on `PerasVoteStake` acknowledges "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." The normalization step is absent from every path between ledger stake lookup and quorum comparison.

---

### Recommendation

Either:
- Normalize each `PerasVoteStake` at validation time (divide by total committee stake) before storing it in `ValidatedPerasVote`, so that `ptvtTotalStake` is always a fraction in `[0,1]`; or
- Change `stakeAboveThreshold` to accept the total committee stake and perform the normalization internally: `stake / totalCommitteeStake >= quorumThreshold + safetyMargin`.

The fix must be applied consistently across `votesReachQuorum`, `updateLoserVoteState`, and any future callers.

---

### Proof of Concept

1. Adversary is a committee member with absolute ledger stake `S` (any positive value).
2. Adversary sends one `PerasVote` for block `B` in round `R` to an honest node.
3. Node calls `processVotes` → `validatePerasVote`: looks up `S` from `PerasVoteStakeDistr`, stores `vpvVoteStake = S`.
4. Node calls `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `updateTargetVoteTally`: `ptvtTotalStake = 0 + S = S`.
5. `votesReachQuorum` calls `stakeAboveThreshold`: `S >= 0.75 + safetyMargin` evaluates to `True` (since `S` is an absolute lovelace value ≫ 1).
6. `forgePerasCert` produces `ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
7. Certificate is inserted into `PerasCertDB`; `implGetWeightSnapshot` returns a snapshot boosting block `B`.
8. `preferAnchoredCandidate` now prefers any chain containing `B` over an equally long honest chain, causing the node to switch to the adversarial fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```
