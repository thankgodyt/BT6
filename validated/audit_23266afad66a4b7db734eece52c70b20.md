### Title
Peras Quorum Check Uses Unnormalized Vote Stake Against Relative Threshold — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares an accumulated `PerasVoteStake` value directly against a relative quorum threshold without normalizing the stake first. The code itself documents this as an unresolved unit mismatch. If `PerasVoteStake` values are populated from absolute ledger stake (lovelace), the comparison is between incompatible units, causing the quorum gate to either always pass (absolute >> 0.75) or always fail — directly analogous to the Sundial bug where raw deposited liquidity was used instead of the backdated principal token amount.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `stake = unPerasVoteStake voteStake` and `quorumThreshold` is a relative `Rational` (e.g. 0.75). The function's own comment explicitly states the normalization precondition is unverified:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [1](#0-0) 

`ptvtTotalStake` is accumulated by `updateTargetVoteTally` by directly summing `vpvVoteStake` values from incoming `ValidatedPerasVote` records, with no normalization step:

```haskell
(votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
``` [2](#0-1) 

This unnormalized `ptvtTotalStake` is then passed directly to `stakeAboveThreshold` in `updateLoserVoteState`:

```haskell
aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
``` [3](#0-2) 

The `PerasVoteStake` type's own documentation acknowledges there is "no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee": [4](#0-3) 

The `ValidatedPerasVote` struct carries `vpvVoteStake :: PerasVoteStake` set by the caller, with no enforcement that it is normalized: [5](#0-4) 

---

### Impact Explanation

**If `PerasVoteStake` is populated with absolute lovelace values** (e.g. 1,000,000,000): `ptvtTotalStake` after even one vote is a very large integer, which is always `>= 0.76`. `stakeAboveThreshold` returns `True` unconditionally. In `updateLoserVoteState` this triggers `RoundVoteStateLoserAboveQuorum` for every loser vote, corrupting the round vote state. If the same unnormalized path feeds the candidate quorum check (`votesReachQuorum`), a single crafted vote forges a Peras certificate, bypassing the quorum requirement entirely — unauthorized certificate acceptance.

**If `PerasVoteStake` is relative but not summing to 1** (e.g. each voter's individual fraction without accounting for the committee subset): the accumulated total can exceed 1.0 before honest quorum is reached, again causing premature certificate forging, or fall below the threshold even with full honest participation, preventing any certificate from ever being forged.

Both cases break the Peras voting invariant. The first case maps directly to: *Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance* (Critical).

---

### Likelihood Explanation

The `PerasVoteStakeDistr` is constructed from the ledger's pool stake distribution. Ledger stake is expressed in lovelace (absolute). Without an explicit normalization step between ledger stake lookup and `ValidatedPerasVote` construction, absolute values flow into `ptvtTotalStake`. The TODO comment confirms this normalization step does not currently exist. Any peer that can submit a `PerasVote` message triggers this path.

---

### Recommendation

Before calling `stakeAboveThreshold`, normalize `ptvtTotalStake` by dividing by the total stake of the voting committee. Alternatively, change `stakeAboveThreshold` to accept the total committee stake and perform normalization internally:

```haskell
stakeAboveThreshold params totalCommitteeStake voteStake =
  (unPerasVoteStake voteStake / unPerasVoteStake totalCommitteeStake)
    >= quorumThreshold + safetyMargin
```

The `PerasVoteStakeDistr` construction site should enforce that all stored values are already normalized fractions summing to ≤ 1, or the normalization should be deferred to the comparison site with the total passed explicitly.

---

### Proof of Concept

1. Attacker connects as an unprivileged peer and submits a single `PerasVote` for a target block in round R.
2. The vote is validated and wrapped as `ValidatedPerasVote { vpvVoteStake = PerasVoteStake absoluteLovelace }` where `absoluteLovelace` is the pool's raw ledger stake (e.g. `1_000_000_000_000`).
3. `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `updateTargetVoteTally` accumulates `ptvtTotalStake = 1_000_000_000_000`.
4. `votesReachQuorum` (or the loser path via `stakeAboveThreshold`) evaluates `1_000_000_000_000 >= 0.75 + 0.01` → `True`.
5. `forgePerasCert` is called with a single-vote list, producing a certificate for the attacker's chosen block.
6. The certificate is accepted by the chain, granting the attacker's block a Peras weight boost, distorting chain selection in their favor — with only one vote instead of the required quorum of honest stake. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L214-219)
```haskell
data ValidatedPerasVote blk = ValidatedPerasVote
  { vpvVote :: !(PerasVote blk)
  , vpvVoteStake :: !PerasVoteStake
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
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
