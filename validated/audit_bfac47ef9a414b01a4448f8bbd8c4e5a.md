### Title
Peras Quorum Check Compares Absolute Stake Against Relative Threshold — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (accumulated from `PerasVoteStakeDistr`, which is populated from the ledger's absolute lovelace stake) directly against `perasQuorumStakeThreshold` (a relative `Rational` value of `3/4`). This is a denomination mismatch: absolute lovelace amounts (e.g., `1_000_000_000`) are compared against a normalized fraction (`0.77`). The comparison always evaluates to `True` for any voter with positive stake, allowing a single vote to forge a Peras certificate and bypass the quorum requirement entirely.

---

### Finding Description

`stakeAboveThreshold` is defined as:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `quorumThreshold = 3/4` and `safetyMargin = 2/100` (from `mkPerasParams`).

The code itself documents the mismatch:

> "TODO: this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function …"

`PerasVoteStake` is assigned during `validatePerasVote` by a direct lookup into `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
```

`PerasVoteStakeDistr` is a `Map PerasVoterId PerasVoteStake` populated from the ledger's stake distribution. The ledger records stake in absolute lovelace (e.g., a pool with 1 billion lovelace has `PerasVoteStake (1_000_000_000 % 1)`). When this absolute value is summed across even a single vote and passed to `stakeAboveThreshold`, the comparison `1_000_000_000 >= 0.77` is trivially `True`.

The call chain is:
1. `processVotes` → `validatePerasVote` (assigns absolute lovelace as `vpvVoteStake`)
2. `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold` (compares absolute lovelace against `3/4`)
3. On `True`: `forgePerasCert` is called, producing a `ValidatedPerasCert` with `vpcCertBoost = perasWeight = 15`

The same mismatch affects `updateLoserVoteState`, which calls `stakeAboveThreshold` to detect the error condition of a loser exceeding quorum — this check would also always fire, causing spurious `RoundVoteStateLoserAboveQuorum` errors that block legitimate vote processing.

---

### Impact Explanation

A Peras certificate with `vpcCertBoost = 15` is accepted by the ChainDB and used in chain selection to add 15 units of weight to the boosted block's chain. An adversary controlling any stake pool (even a minimal one) can:

1. Cast a single `PerasVote` for any block of their choosing.
2. The vote passes `validatePerasVote` (voter found in stake distribution with absolute lovelace stake).
3. `stakeAboveThreshold` returns `True` immediately (absolute lovelace >> `0.77`).
4. A `ValidatedPerasCert` is forged and submitted to the ChainDB.
5. The adversary's chosen block gains a 15-block chain-weight boost.
6. Honest nodes running chain selection will prefer the adversary's boosted chain over the canonical chain, causing divergence.

This is a bypass of the Peras quorum/certificate check that enables unauthorized certificate acceptance and chain-selection manipulation by any unprivileged peer with any positive stake.

---

### Likelihood Explanation

The current production wiring in `NodeToNode.hs` passes `pure (PerasVoteStakeDistr mempty)` — an empty distribution — so all votes currently fail validation (no voter is found). However, the code is explicitly marked as incomplete with TODOs for connecting the real ledger stake distribution. Once that plumbing is completed (the stated next step in the codebase), the mismatch becomes immediately exploitable. Any stake pool operator on the network becomes an unprivileged attacker capable of forging certificates.

---

### Recommendation

Before connecting the real ledger stake distribution to `PerasVoteStakeDistr`, normalize each voter's absolute lovelace stake to a relative fraction of the total committee stake. Either:

1. Normalize at population time: divide each voter's absolute stake by the total stake of all committee members when constructing `PerasVoteStakeDistr`, so each entry is in `[0, 1]`.
2. Normalize at comparison time: change `stakeAboveThreshold` to accept the total stake as an additional parameter and compute `stake / totalStake >= threshold` internally.
3. Change `perasQuorumStakeThreshold` to be expressed in absolute lovelace units consistent with the ledger's representation.

Option 1 is preferred as it aligns with the existing comment's intent and keeps the threshold semantics as a relative fraction.

---

### Proof of Concept

**Root cause — denomination mismatch in `stakeAboveThreshold`:** [1](#0-0) 

**Quorum threshold is a relative `Rational` (`3/4`):** [2](#0-1) 

**`vpvVoteStake` is assigned directly from `PerasVoteStakeDistr` without normalization:** [3](#0-2) 

**`votesReachQuorum` sums raw `vpvVoteStake` values and calls `stakeAboveThreshold`:** [4](#0-3) 

**`updateCandidateVoteState` calls `votesReachQuorum` and forges a cert on `True`:** [5](#0-4) 

**`updateLoserVoteState` also calls `stakeAboveThreshold` with the same mismatch:** [6](#0-5) 

**Current production wiring uses empty distribution (masks the bug today):** [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L400-408)
```haskell
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
