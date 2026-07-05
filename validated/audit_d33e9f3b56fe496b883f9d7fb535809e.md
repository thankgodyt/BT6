### Title
Peras Quorum Check Compares Unnormalized Vote Stake Against Normalized Threshold, Enabling Invalid Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` directly compares the accumulated `PerasVoteStake` (which may be an absolute ledger-stake value) against `perasQuorumStakeThreshold` (a relative/normalized `Rational` fraction). The code itself carries a `TODO` comment acknowledging this unit mismatch. If `PerasVoteStake` values are absolute, quorum is trivially reached by any single voter, allowing an unprivileged peer to cause acceptance of an invalid Peras certificate and inject an arbitrary chain-weight boost into chain selection.

---

### Finding Description

`stakeAboveThreshold` is the sole gate that decides whether a set of Peras votes constitutes a quorum and therefore whether a `ValidatedPerasCert` is forged and stored:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs
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
  stake     = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
``` [1](#0-0) 

`PerasVoteStake` is `newtype … Rational` and `PerasQuorumStakeThreshold` is also `newtype … Rational`, but they represent different domains: the threshold is a relative fraction (e.g. `0.75` meaning 75 % of total stake), while `vpvVoteStake` is accumulated from individual voter weights that are derived from raw `LedgerStake` (absolute lovelace counts). [2](#0-1) 

The accumulation path is:

1. `updateTargetVoteTally` sums `vpvVoteStake` from each `ValidatedPerasVote` into `ptvtTotalStake`. [3](#0-2) 
2. `updateCandidateVoteState` calls `votesReachQuorum cfg voteList`. [4](#0-3) 
3. `votesReachQuorum` calls `stakeAboveThreshold cfg totalVoteStake` with the raw accumulated sum. [5](#0-4) 

For persistent committee members, `implEligiblePartyVoteWeight` returns `VoteWeight stake` where `stake` is the raw `LedgerStake` integer — an absolute lovelace count, not a fraction of total stake. [6](#0-5) 

If `vpvVoteStake` is populated from this absolute value (e.g. `1_000_000` lovelace expressed as `Rational`), then `totalVoteStake` after even a single vote vastly exceeds `perasQuorumStakeThreshold` (e.g. `0.75`). Quorum is trivially satisfied by any single voter, regardless of how much of the total stake they actually hold.

The analog to the external report is exact: `_amount` (nominal USDC) was used without converting to its real USD value; here, absolute ledger stake is used without normalizing to a fraction of total stake.

---

### Impact Explanation

A forged `ValidatedPerasCert` is stored in `PerasCertDB` and its `vpcCertBoost` (`PerasWeight`) is added to the `PerasWeightSnapshot`. [7](#0-6) 

That snapshot is used directly in `preferAnchoredCandidate` and `compareAnchoredFragments` to decide which chain to adopt. [8](#0-7) 

`wsvTotalWeight` adds `wsvBlockNo` and `wsvWeightBoost` together; a fraudulently large boost can make a shorter, adversary-controlled chain appear heavier than the honest chain. [9](#0-8) 

**Impact class**: High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

- Peras votes arrive over the network mini-protocol from any peer; no privileged access is required.
- A single persistent committee member (or any party whose `vpvVoteStake` is absolute) can trigger the condition.
- The `TODO` comment in the production source confirms the developers are aware the normalization is missing and have not yet resolved it.
- The condition is deterministic: if the unit mismatch exists, it fires on every vote from a voter with non-trivial absolute stake.

---

### Recommendation

1. **Normalize before comparing**: Before calling `stakeAboveThreshold`, divide the accumulated `PerasVoteStake` by the total active stake to produce a relative fraction, or pass the total stake into `stakeAboveThreshold` and perform the division internally.
2. **Enforce units at the type level**: Introduce distinct newtypes for absolute stake and relative stake so the compiler rejects direct comparisons across units.
3. **Resolve the TODO**: The comment at line 153–161 of `SupportsPeras.hs` explicitly flags this assumption; it must be resolved before Peras is enabled on any production network.

---

### Proof of Concept

Assume:
- Total active stake = 10,000,000 lovelace.
- `perasQuorumStakeThreshold` = `0.75` (75 % of total stake required).
- Adversary controls a pool with `LedgerStake = 1` lovelace (0.00001 % of total stake).
- `vpvVoteStake` is set to the absolute value `1 % 1` (Rational).

After the adversary submits one vote:
```
totalVoteStake = PerasVoteStake (1 % 1)
quorumThreshold + safetyMargin ≈ 0.75 + ε
stake (1.0) >= 0.75 + ε  →  True
```

Quorum is declared reached. A `ValidatedPerasCert` is forged for the adversary's chosen block, `vpcCertBoost` is added to the `PerasWeightSnapshot`, and `chainSelectionForBlock` is triggered for the boosted block. [10](#0-9)  The adversary's chain now carries an illegitimate weight boost, causing honest nodes to prefer it over the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L148-152)
```haskell
  deriving stock Generic
  deriving Show via Quiet PerasVoteStake
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L413-417)
```haskell
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L143-149)
```haskell
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```
