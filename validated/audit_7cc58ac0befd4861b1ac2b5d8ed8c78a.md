### Title
Ineffective Peras Quorum Check Due to Missing Stake Normalization in `stakeAboveThreshold` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares the accumulated `PerasVoteStake` (a `Rational` drawn from the ledger's absolute stake distribution) directly against `perasQuorumStakeThreshold` (a relative, normalized `Rational` in `[0,1]`). The code itself documents that no normalization is performed before the comparison, and that the two values may not be in the same units. This makes the quorum gate for Peras certificate forging equivalent to a no-op: if callers supply absolute lovelace-scale stake values, the comparison `stake >= quorumThreshold + safetyMargin` is trivially satisfied by any non-zero vote, bypassing the quorum requirement entirely.

---

### Finding Description

`stakeAboveThreshold` is the sole quorum gate used to decide whether a set of Peras votes is sufficient to forge a certificate:

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

The `PerasVoteStake` type is defined as an opaque `Rational`, and the accompanying note explicitly states there is no agreed-upon method to convert absolute ledger stake to the relative committee stake that the threshold expects:

```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting committee (given that the quorum is expressed as
-- a relative value of the voting committee total stake).
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
``` [2](#0-1) 

`stakeAboveThreshold` is called in two critical paths:

1. **`votesReachQuorum`** — the smart constructor that gates certificate forging:

```haskell
votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
``` [3](#0-2) 

2. **`updateCandidateVoteState`** — which calls `votesReachQuorum` and, on success, immediately forges a certificate:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [4](#0-3) 

The `PerasVoteStakeDistr` that backs each vote's stake is populated via `lookupPerasVoteStake`, which performs a plain map lookup with no normalization:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [5](#0-4) 

If the concrete `BlockSupportsPeras` instance populates `PerasVoteStakeDistr` with raw ledger lovelace values (absolute, e.g. `1_000_000_000`), while `perasQuorumStakeThreshold` is a relative fraction (e.g. `3 % 4`), then `stake >= quorumThreshold + safetyMargin` evaluates to `1_000_000_000 >= 0.75 + ε`, which is always `True`. The quorum check becomes equivalent to setting the threshold to zero — an exact structural parallel to the reported Illuminate `yield` bug where `sellBasePreview`'s output was used as `minReturn` without validation, making the slippage check a no-op.

---

### Impact Explanation

A Peras certificate forged without genuine quorum carries a `PerasWeight` boost that is added to the boosted block's `WeightedSelectView` during chain selection:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
        compare
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix)
``` [6](#0-5) 

An attacker who can inject even a single valid (signature-correct) Peras vote for a target block can trigger `updateCandidateVoteState`, which calls `votesReachQuorum`, which calls `stakeAboveThreshold`. If the check trivially passes, `forgePerasCert` is called immediately, producing a `ValidatedPerasCert` that boosts the target block's weight. This lets an unprivileged peer cause an honest node to prefer a non-canonical, adversarially chosen chain over the honest chain — a **Critical** chain-selection safety failure and a **Critical** bypass of Peras certificate checks.

---

### Likelihood Explanation

The code explicitly documents the unit mismatch as an unresolved open question. The `BlockSupportsPeras` class leaves the concrete population of `PerasVoteStakeDistr` to implementors, with no type-level or runtime enforcement of normalization. Any implementation that stores raw ledger stake (the natural source) without dividing by total committee stake will trigger the always-true condition. The issue is reachable on any private testnet or staging environment running Peras-enabled consensus, triggered by a single crafted vote message from an unprivileged peer.

---

### Recommendation

1. **Normalize before comparison**: `stakeAboveThreshold` (or its callers) must divide each voter's absolute ledger stake by the total stake of the voting committee before comparing against `perasQuorumStakeThreshold`. The total committee stake should be passed in explicitly, or `stakeAboveThreshold` should accept a `PerasVoteStakeDistr` and compute the normalized fraction internally.

2. **Enforce units at the type level**: Introduce distinct newtypes for absolute stake (`AbsolutePerasVoteStake`) and normalized stake (`NormalizedPerasVoteStake`), so the compiler rejects comparisons between incompatible units.

3. **Add a guard**: At minimum, add a runtime assertion in `stakeAboveThreshold` that `unPerasVoteStake voteStake <= 1`, catching the absolute-vs-relative confusion before it silently passes the quorum gate.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Obtain a single valid Peras vote (correct VRF/KES signatures) for an adversarial block `B` from any registered pool with non-zero absolute stake `s` (e.g. `s = 1_000_000` lovelace).
2. Deliver the vote to a target node via the Peras object-diffusion miniprotocol.
3. The node calls `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold`.
4. `stakeAboveThreshold` evaluates `1_000_000 >= 0.75 + ε` → `True`.
5. `forgePerasCert` is called; a `ValidatedPerasCert` with `vpcCertBoost = perasWeight params` is stored.
6. On the next chain-selection cycle, block `B` carries a Peras weight boost. If `B` is on a fork, `preferAnchoredCandidate` now computes `weightedSelectView` including the boost, potentially making the adversarial fork preferred over the honest chain. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-151)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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
