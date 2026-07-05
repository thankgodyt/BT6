### Title
Peras Quorum Check Compares Unnormalized `PerasVoteStake` Against Relative Threshold Without Unit Adjustment - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` directly compares the raw `PerasVoteStake` value against `perasQuorumStakeThreshold` without enforcing that both quantities are expressed in the same unit (absolute vs. relative). The code itself documents this assumption as unverified. If `PerasVoteStake` carries absolute ledger stake (in lovelace) while the quorum threshold is a relative fraction of total committee stake, a single vote from any pool with non-trivial stake trivially satisfies the quorum check, allowing unauthorized Peras certificate acceptance.

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `stake = unPerasVoteStake voteStake` and `quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)`.

Both sides are unwrapped `Rational` values, but the code carries an explicit TODO acknowledging that the two sides may not be in the same unit: [1](#0-0) 

The `PerasVoteStake` type itself carries a NOTE confirming that no normalization from absolute ledger stake to relative committee stake has been implemented: [2](#0-1) 

`PerasQuorumStakeThreshold` is documented as a relative value (fraction of total committee stake): [3](#0-2) 

The `validatePerasVote` implementation for `TestBlock` (the only concrete `BlockSupportsPeras` instance) copies the stake directly from `PerasVoteStakeDistr` into `ValidatedPerasVote.vpvVoteStake` with no normalization: [4](#0-3) 

`stakeAboveThreshold` is then called on the accumulated `PerasVoteStake` in `votesReachQuorum`: [5](#0-4) 

which is called from `updateCandidateVoteState` to decide whether to forge a certificate: [6](#0-5) 

### Impact Explanation

**Critical — Bypass of Peras certificate/vote quorum check enabling unauthorized certificate acceptance.**

If `PerasVoteStakeDistr` is populated with absolute ledger stake values (e.g., lovelace amounts such as `1_000_000_000_000 % 1`) while `perasQuorumStakeThreshold` is set to a relative value (e.g., `3 % 4` for 75%), then `stake >= quorumThreshold` evaluates `1_000_000_000_000 >= 0.75`, which is always `True`. A single valid vote from any pool with non-trivial stake immediately satisfies quorum, and `forgePerasCert` is called, producing a `ValidatedPerasCert` for an arbitrary block. This completely bypasses the Peras quorum requirement, allowing an attacker to boost any block — including an adversarial fork — with a certificate weight of `perasWeight`, directly corrupting chain selection.

Conversely, if absolute stake values are small fractions (e.g., `1 % 10_000_000_000`), quorum is never reachable, permanently suppressing Peras certificate production. The first direction (trivial quorum) is the security-critical path.

### Likelihood Explanation

The Peras protocol is in active development and not yet deployed on mainnet, but the production code path (`updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold`) is fully wired. Any node operator who populates `PerasVoteStakeDistr` from raw ledger stake (the natural and undocumented-otherwise approach) will trigger this bug. An unprivileged peer only needs to send a single cryptographically valid vote (correct voter ID, valid signature) to cause the node to forge an unauthorized certificate. No stake majority, key compromise, or privileged access is required.

### Recommendation

`stakeAboveThreshold` must not accept a raw `PerasVoteStake` without a normalization guarantee. Two concrete fixes:

1. **Normalize at the call site**: Before calling `stakeAboveThreshold`, divide the accumulated `PerasVoteStake` by the total committee stake so the result is a relative fraction in `[0,1]`, matching the unit of `perasQuorumStakeThreshold`.

2. **Enforce normalization inside the function**: Change `stakeAboveThreshold` to accept the total committee stake as an additional parameter and perform the division internally:
   ```haskell
   stakeAboveThreshold :: PerasParams -> TotalCommitteeStake -> PerasVoteStake -> Bool
   stakeAboveThreshold params totalStake voteStake =
     (unPerasVoteStake voteStake / totalStake) >= quorumThreshold + safetyMargin
   ```

The `PerasVoteStake` newtype should be split into `AbsolutePerasVoteStake` and `RelativePerasVoteStake` (or use a phantom type parameter) to make the unit distinction statically enforced, preventing future callers from making the same mistake.

### Proof of Concept

Given `mkPerasParams` defaults and a `PerasVoteStakeDistr` populated with absolute lovelace stake:

```haskell
-- Attacker controls a pool with 1 ADA of stake (absolute)
let stakeDistr = PerasVoteStakeDistr $
      Map.singleton attackerVoterId (PerasVoteStake (1_000_000 % 1))  -- 1 ADA in lovelace

-- perasQuorumStakeThreshold is a relative value, e.g. 3/4
-- stakeAboveThreshold evaluates: 1_000_000 >= 0.75 + safetyMargin  →  True

-- A single valid vote from the attacker immediately reaches quorum:
let vote = ValidatedPerasVote { vpvVote = attackerVote, vpvVoteStake = PerasVoteStake (1_000_000 % 1) }
-- votesReachQuorum cfg [vote]  →  Just (ValidatedPerasVotesWithQuorum ...)
-- forgePerasCert is called → unauthorized certificate for attacker's chosen block
```

The attacker sends one network message (a valid `PerasVote` over the ObjectDiffusion mini-protocol). The receiving node calls `updatePerasRoundVoteStates`, which calls `updateCandidateVoteState`, which calls `votesReachQuorum`, which calls `stakeAboveThreshold` with the absolute stake value, which returns `True`, causing `forgePerasCert` to produce a `ValidatedPerasCert` boosting the attacker's chosen block by `perasWeight` in chain selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L93-98)
```haskell
-- | Total stake needed to forge a Peras certificate.
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
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
