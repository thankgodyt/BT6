### Title
Unit/Scale Mismatch in Peras Quorum Threshold Check Allows Incorrect Certificate Acceptance - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares an accumulated `PerasVoteStake` value directly against a relative quorum threshold (`3/4`) without normalizing the vote stake to the same unit. The code itself documents this as an unresolved unit mismatch. If `PerasVoteStake` values sourced from the ledger are absolute (e.g., lovelace amounts) rather than relative fractions, the comparison is semantically equivalent to the external report's `msg.value / taxCut` bug: two quantities expressed in incompatible units are compared as if they were the same, producing a result that is either always true or always false.

---

### Finding Description

`PerasVoteStake` is a `Rational` newtype whose intended semantics are explicitly unresolved: [1](#0-0) 

The comment states:

> "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."

The quorum check itself carries a matching TODO:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

Despite this, `stakeAboveThreshold` performs a bare numeric comparison with no normalization step: [2](#0-1) 

The quorum threshold is a relative value (`3/4`) set in `mkPerasParams`: [3](#0-2) 

Vote stake is accumulated by summing raw `vpvVoteStake` values without normalization: [4](#0-3) 

The accumulated total is then passed directly to `stakeAboveThreshold`: [5](#0-4) 

The `validatePerasVote` path (the degenerate instance used for all blocks) assigns the raw ledger-sourced stake to `vpvVoteStake` with no normalization: [6](#0-5) 

---

### Impact Explanation

This is a **High** impact finding. The Peras quorum check is the gate that determines whether a `ValidatedPerasCert` is forged and accepted into the chain. A unit mismatch here produces one of two failure modes:

1. **Absolute stake >> 3/4 (e.g., lovelace amounts):** `stakeAboveThreshold` returns `True` for every single vote, meaning any unprivileged peer that sends one valid vote immediately triggers certificate forging for an arbitrary block. This bypasses the quorum requirement entirely, allowing unauthorized certificate acceptance and chain-selection manipulation via the Peras boost weight.

2. **Absolute stake << 3/4 (e.g., fractional lovelace or very small values):** `stakeAboveThreshold` never returns `True`, meaning legitimate quorum is never reached and the Peras protocol is permanently broken for all honest nodes.

Both outcomes break the Peras voting/certificate invariant and constitute a consensus safety failure matching the "Bypass of certificate/vote/certificate checks" and "Chain selection bug" impact categories.

---

### Likelihood Explanation

**Medium.** The ledger naturally expresses stake in absolute units (lovelace). The `PerasVoteStakeDistr` is populated from ledger state. Unless a normalization step is explicitly inserted before `validatePerasVote` is called — which the code explicitly says has not been decided — the mismatch will manifest in any deployment that uses real ledger stake distributions. An unprivileged peer only needs to send a single syntactically valid vote to trigger the incorrect quorum check.

---

### Recommendation

1. Decide and enforce the unit of `PerasVoteStake`: it must be a relative fraction in `[0, 1]` representing the voter's share of total committee stake.
2. Normalize the stake inside `validatePerasVote` (or inside `stakeAboveThreshold`) by dividing the voter's absolute ledger stake by the total stake of the `PerasVoteStakeDistr` before storing it in `vpvVoteStake`.
3. Add a type-level or runtime invariant asserting that the sum of all `PerasVoteStake` values in a `PerasVoteStakeDistr` equals `1`, analogous to the BPS boundary check recommended in the external report.
4. Remove the TODO comments only after the normalization is implemented and tested.

---

### Proof of Concept

Assume `PerasVoteStakeDistr` is populated with absolute lovelace values (e.g., voter A has `1_000_000` lovelace out of `10_000_000` total). Then:

```
vpvVoteStake A = PerasVoteStake (1_000_000 % 1)
totalVoteStake = PerasVoteStake (1_000_000 % 1)   -- after one vote
quorumThreshold + safetyMargin = 3/4 + 2/100 = 77/100
stakeAboveThreshold: 1_000_000 >= 77/100  →  True
```

A single vote from peer A immediately forges a `ValidatedPerasCert` for any block A names, regardless of whether honest stake actually reached quorum. The node accepts this certificate and applies the Peras chain-selection boost to A's chosen block, diverging from the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-161)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
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
