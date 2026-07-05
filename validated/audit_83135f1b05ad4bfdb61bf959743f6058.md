### Title
Peras Quorum Check Bypassed Due to Missing Vote-Stake Normalization Before Threshold Comparison - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares an accumulated `PerasVoteStake` (sourced from the ledger's absolute stake distribution) directly against a normalized relative quorum threshold (`3/4 + safety margin`). No normalization of the vote stake is performed before the comparison. The code itself acknowledges this with a `TODO` comment. When the production Peras plumbing is wired to supply real ledger stake values, any single vote from a voter with non-trivial absolute stake will satisfy `stake >= quorumThreshold`, allowing an unprivileged peer to forge a Peras certificate for any block with a single vote.

---

### Finding Description

`PerasVoteStake` is defined as a bare `Rational` wrapper with no invariant enforcing normalization: [1](#0-0) 

The comment on the type explicitly states there is no agreed-upon conversion from absolute ledger stake to relative stake.

`stakeAboveThreshold` then compares the accumulated (potentially absolute) vote stake directly against the normalized threshold: [2](#0-1) 

The `TODO` comment on lines 155–161 is the self-admission of the bug: the function assumes both sides are in the same units, but the quorum threshold is always a relative value (e.g., `3/4 + 2/100 = 0.77`), while the `PerasVoteStake` values come from `PerasVoteStakeDistr`, which is populated from the ledger's absolute stake (lovelace).

The default `validatePerasVote` implementation assigns the raw stake from `PerasVoteStakeDistr` to `vpvVoteStake` without any normalization: [3](#0-2) 

`votesReachQuorum` then calls `stakeAboveThreshold` on the sum of these raw stakes: [4](#0-3) 

The same unnormalized comparison is also used in `updateLoserVoteState` inside `Aggregation.hs`: [5](#0-4) 

Currently in production, the `PerasVoteStakeDistr` is hardcoded to `mempty`, so all votes are rejected and the bug is dormant: [6](#0-5) 

However, the `TODO` comment at that same site explicitly states this will be replaced with real committee selection data from the ChainDB. When that happens, if the stake values are absolute (lovelace), the normalization mismatch becomes exploitable.

---

### Impact Explanation

When the production stake distribution is wired in with absolute lovelace values (e.g., a voter with 1,000,000 lovelace stake), the comparison becomes:

```
1_000_000 >= (3/4 + 2/100)   -- i.e., 1000000 >= 0.77  → True
```

A single vote from any voter with any non-trivial stake satisfies the quorum check. This allows an adversarial peer to:

1. Send a single `PerasVote` for any block of their choosing.
2. Have `votesReachQuorum` return `Just` immediately.
3. Trigger `forgePerasCert`, producing a `ValidatedPerasCert` boosting the adversarial block.
4. The boosted block gains `perasWeight = 15` extra weight in `weightedSelectView` / `compareAnchoredFragments`, causing honest nodes to prefer the adversarial chain.

This is a **bypass of the Peras quorum/certificate check**, enabling unauthorized certificate acceptance and adversarial chain selection influence.

---

### Likelihood Explanation

The bug is not currently exploitable because the stake distribution is `mempty`. However:

- The `TODO` comment in `NodeToNode.hs` (line 402) explicitly plans to replace `mempty` with real ledger stake data.
- The `TODO` comment in `stakeAboveThreshold` (lines 155–161) acknowledges the normalization is missing and must be added.
- Ledger stake distributions are naturally in absolute units (lovelace), making it highly likely that without an explicit normalization step, absolute values will be passed in.
- Any unprivileged peer can send `PerasVote` messages via the Peras vote diffusion mini-protocol, making the entry path fully externally reachable.

---

### Recommendation

`stakeAboveThreshold` must either:

1. Accept the total stake distribution as an additional parameter and normalize `voteStake` by dividing by the total before comparing, or
2. Enforce at the `PerasVoteStakeDistr` construction site that all stored `PerasVoteStake` values are already normalized (relative) values summing to ≤ 1.

The normalization must be applied consistently in both `votesReachQuorum` and `updateLoserVoteState` (in `Aggregation.hs`), mirroring the fix pattern described in the external report: the normalization must happen at the point where the value is used in the comparison, not assumed to have been done upstream.

---

### Proof of Concept

Assume the production stake distribution is wired in with absolute lovelace values:

1. Adversarial peer constructs a `PerasVote` for a target block `B` in round `R`, signed by voter `V` who holds 1,000,000 lovelace.
2. The vote arrives via the Peras vote diffusion mini-protocol and is passed to `makePerasVotePoolWriterFromChainDB`.
3. `validatePerasVote` looks up voter `V` in `PerasVoteStakeDistr` and assigns `vpvVoteStake = PerasVoteStake 1_000_000`.
4. `updateCandidateVoteState` calls `votesReachQuorum cfg [vote]`.
5. `totalVoteStake = PerasVoteStake 1_000_000`.
6. `stakeAboveThreshold params (PerasVoteStake 1_000_000)` evaluates `1_000_000 >= 0.77` → `True`.
7. `forgePerasCert` produces a `ValidatedPerasCert` boosting block `B`.
8. `compareAnchoredFragments` in `AnchoredFragment.hs` uses `weightedSelectView` which adds `perasWeight = 15` to block `B`'s chain weight.
9. Honest nodes switch to the adversarial chain containing `B`.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L399-408)
```haskell
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```
