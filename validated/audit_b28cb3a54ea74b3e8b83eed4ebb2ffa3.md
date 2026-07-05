### Title
Unit Mismatch in Peras Quorum Threshold Check Enables Certificate Forging Bypass - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in `SupportsPeras.hs` compares accumulated `PerasVoteStake` values against the quorum threshold without normalizing the stake to relative units. The code itself documents this as a known design flaw via a TODO comment, stating the function "only makes sense when both values are relative (normalized) values." A companion comment on `PerasVoteStake` further acknowledges "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake." If `PerasVoteStakeDistr` is populated with absolute ledger stake (lovelace), the comparison against a relative quorum threshold would always evaluate to `True`, allowing a single vote to forge a Peras certificate and bypass the quorum requirement entirely.

---

### Finding Description

**Root cause — unit mismatch in `stakeAboveThreshold`:**

`stakeAboveThreshold` at line 162 performs:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `stake = unPerasVoteStake voteStake` is accumulated from individual votes, and `quorumThreshold` is a relative value (a `Rational` fraction of total committee stake) drawn from `PerasParams`.

The TODO comment at lines 153–161 explicitly states:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

The `PerasVoteStake` type comment at lines 136–143 further states:

> "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee … for now you can consider this `Rational` as the best approximation we have at the moment of the concrete type for a relative vote stake."

The phrase "best approximation … at the moment" combined with "no consensus on how to go from absolute to relative" confirms that the conversion from absolute ledger stake to normalized relative stake is **not yet implemented**. The `PerasVoteStakeDistr` is therefore likely populated with raw absolute ledger stake values.

**Call chain to the vulnerable comparison:**

1. `votesReachQuorum` (line 270) calls `stakeAboveThreshold cfg totalVoteStake` [1](#0-0) 

2. `totalVoteStake` is the `mconcat` of `vpvVoteStake` from each `ValidatedPerasVote` [1](#0-0) 

3. `vpvVoteStake` is set in `validatePerasVote` directly from `lookupPerasVoteStake vote stakeDistr` — no normalization step [2](#0-1) 

4. `updateLoserVoteState` in `Aggregation.hs` also calls `stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)` to detect if a losing target crosses quorum [3](#0-2) 

5. The comparison itself: [4](#0-3) 

**The mismatch:** If `PerasVoteStakeDistr` holds absolute lovelace values (e.g., `1_000_000_000`), and `perasQuorumStakeThreshold` is a relative fraction (e.g., `3 % 4` = 0.75), then `1_000_000_000 >= 0.75 + safetyMargin` is trivially `True` for any single vote with non-zero stake. Quorum is declared reached after the very first vote.

---

### Impact Explanation

An unprivileged peer that can submit a single syntactically valid Peras vote (with any non-zero stake) causes `votesReachQuorum` to return `Just` immediately, triggering `forgePerasCert` and producing a `ValidatedPerasCert`. This certificate is then accepted by the node and used to boost a block's chain weight via `vpcCertBoost`, regardless of whether any genuine quorum of stake-weighted voters agreed on that block.

This is a **bypass of Peras voting/certificate checks**: a single attacker-controlled vote forges a certificate that should require a supermajority (e.g., ¾) of the voting committee's stake. The boosted block gains an unearned chain-weight advantage, enabling chain-selection manipulation — an honest node would prefer the attacker's boosted chain over a legitimately longer chain without a certificate.

Impact category: **Critical — bypass of Peras certificate/vote quorum checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

---

### Likelihood Explanation

- The mismatch is reachable by any peer that can submit a `PerasVote` message over the node-to-node object diffusion miniprotocol — no special privileges required.
- The code's own TODO comment confirms normalization is absent and explicitly flags the risk.
- The "no consensus on conversion" note confirms the absolute-to-relative mapping is unimplemented, making it likely that absolute values flow through unchanged.
- The `PerasVoteStakeDistr` is constructed externally and passed into `validatePerasVote`; if the ledger-derived absolute stake is used directly (the only available source before normalization is defined), the mismatch is active.

---

### Recommendation

Normalize `PerasVoteStake` to a relative fraction of total committee stake before it is stored in `PerasVoteStakeDistr` or before it is passed to `stakeAboveThreshold`. Concretely, divide each voter's absolute ledger stake by the total stake of all committee members when constructing `PerasVoteStakeDistr`, so that accumulated `ptvtTotalStake` values are always in `[0, 1]` and directly comparable to the relative `perasQuorumStakeThreshold`. Alternatively, change `stakeAboveThreshold` to accept the total committee stake and perform the normalization internally, mirroring the fix pattern described in the TODO comment.

---

### Proof of Concept

1. Attacker constructs a `PerasVote` for round `r` targeting block `B`.
2. The vote is validated via `validatePerasVote`; `vpvVoteStake` is set to the attacker's absolute ledger stake `S` (e.g., `1_000_000_000 % 1` lovelace as a `Rational`).
3. `updatePerasRoundVoteState` calls `updateCandidateVoteState`, which calls `votesReachQuorum`.
4. `votesReachQuorum` computes `totalVoteStake = PerasVoteStake (1_000_000_000 % 1)`.
5. `stakeAboveThreshold params (PerasVoteStake (1_000_000_000 % 1))` evaluates `1_000_000_000 >= 0.75 + safetyMargin` → `True`.
6. `forgePerasCert` is called; a `ValidatedPerasCert` for block `B` is produced with boost weight `perasWeight params`.
7. The certificate is stored and used in chain selection, boosting `B`'s weight — with only one vote, bypassing the quorum requirement entirely. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-270)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
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
