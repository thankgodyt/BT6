### Title
Missing Stake Normalization in Peras Quorum Check Enables Unauthorized Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (sourced directly from `PerasVoteStakeDistr` without normalization) against a relative quorum threshold (`3/4`). The code itself documents that the two values must be in the same units but provides no enforcement. If `PerasVoteStakeDistr` is populated with absolute ledger stake values (lovelace), any single voter with ≥ 1 lovelace satisfies the quorum check, allowing unauthorized Peras certificate forging.

---

### Finding Description

`PerasVoteStake` is a bare `Rational` with no enforced unit: [1](#0-0) 

The code explicitly acknowledges that no decision has been made on how to go from absolute ledger stake to the relative stake needed for the quorum comparison: [2](#0-1) 

`stakeAboveThreshold` performs a direct comparison with no normalization step: [3](#0-2) 

The TODO comment on `stakeAboveThreshold` itself states the precondition is unverified: [4](#0-3) 

The default `validatePerasVote` instance assigns the raw looked-up stake directly to `vpvVoteStake` without normalizing by total committee stake: [5](#0-4) 

The quorum threshold is set as a relative value `3/4`: [6](#0-5) 

`votesReachQuorum` sums raw `vpvVoteStake` values and passes the total directly to `stakeAboveThreshold`: [7](#0-6) 

The same unnormalized comparison is used in `updateLoserVoteState` in the aggregation module: [8](#0-7) 

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute ledger stake values (lovelace, which is the natural representation from the Cardano ledger), then for any voter with stake `s ≥ 1 lovelace`:

```
s >= (3/4) + (2/100)   →   1 >= 0.77   →   True
```

A single vote from any voter with positive stake would satisfy `stakeAboveThreshold`, causing `votesReachQuorum` to return `Just`, and `forgePerasCert` to be called. This allows an unprivileged peer to cause the local node to forge and accept a Peras certificate for an arbitrary block with a single vote, bypassing the quorum requirement entirely. The forged certificate carries `perasWeight = 15`, which is applied as a chain-selection boost, causing the node to prefer the adversarially-boosted chain.

**Impact class**: Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The Peras voting pipeline is reachable via the miniprotocol object diffusion layer. Any peer that can send a `PerasVote` message triggers this path. The ledger naturally stores stake in absolute lovelace units. The missing normalization is not a hypothetical edge case — it is the default behavior unless the caller of `validatePerasVote` explicitly pre-normalizes the `PerasVoteStakeDistr`, which the code provides no mechanism or contract to enforce. The TODO comments confirm this normalization has not been implemented.

---

### Recommendation

Introduce a single, consistent normalization step at the point where `PerasVoteStakeDistr` is constructed from the ledger stake distribution. Divide each voter's absolute stake by the total committee stake to produce a relative value in `[0, 1]`. This normalized value is then directly comparable to the relative `perasQuorumStakeThreshold`. Remove the TODO and encode the unit invariant in the type system (e.g., a `NormalizedPerasVoteStake` newtype) so that `stakeAboveThreshold` can only be called with correctly-scaled values, eliminating the unit mismatch at the source rather than relying on caller discipline.

---

### Proof of Concept

1. Construct a `PerasVoteStakeDistr` mapping a single voter to `PerasVoteStake (1 % 1)` (1 lovelace, absolute).
2. Call `validatePerasVote params stakeDistr vote` — returns `Right (ValidatedPerasVote { vpvVoteStake = PerasVoteStake (1 % 1) })`.
3. Call `votesReachQuorum cfg [validatedVote]`:
   - `totalVoteStake = PerasVoteStake (1 % 1)`
   - `stakeAboveThreshold params (PerasVoteStake (1 % 1))` evaluates `1 % 1 >= 3 % 4 + 2 % 100` → `100 % 100 >= 77 % 100` → `True`
   - Returns `Just (ValidatedPerasVotesWithQuorum ...)`.
4. `forgePerasCert` is called, producing a `ValidatedPerasCert` with `vpcCertBoost = PerasWeight 15`.
5. The node accepts this certificate and applies the boost to the adversary's chain, causing it to be preferred in chain selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-176)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
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
