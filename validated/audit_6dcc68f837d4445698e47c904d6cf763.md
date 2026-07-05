### Title
Missing Stake Normalization in Peras Quorum Check Bypasses Certificate Threshold - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares a raw `PerasVoteStake` value directly against the relative `perasQuorumStakeThreshold` without dividing by the total committee stake. This is the exact structural analog of the reported bug: a product (accumulated vote stake) is compared against a threshold that is expressed in a different unit (relative fraction), with the normalizing denominator (total stake) absent. The code itself documents this defect with an explicit TODO.

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the quorum check as:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake     = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (...)
``` [1](#0-0) 

The code comment immediately above this function states the defect explicitly:

> "this function only makes sense when both values are relative (normalized) values, so we should either **normalize the `PerasVoteStake` before calling this function**, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `PerasVoteStake` type is described as having no settled normalization convention:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [3](#0-2) 

`votesReachQuorum` accumulates `PerasVoteStake` values from all votes and passes the sum

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
