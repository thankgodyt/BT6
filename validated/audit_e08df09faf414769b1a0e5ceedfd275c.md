### Title
Peras Quorum Check Compares Unnormalized Vote Stake Against Relative Threshold, Enabling Invalid Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares the accumulated `PerasVoteStake` — sourced directly from `PerasVoteStakeDistr` without normalization — against `perasQuorumStakeThreshold`, which is a relative value (e.g., `3/4`). The code's own comment explicitly acknowledges that these two operands may be in different units (absolute vs. relative), and that normalization is absent. This is a direct analog to the stable-swap decimal-normalization bug: just as unnormalized token amounts with different decimal precisions corrupt the invariant D computation, unnormalized absolute stake values corrupt the Peras quorum check, enabling either trivial quorum satisfaction (any single vote passes) or permanent quorum impossibility.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `quorumThreshold = 3/4` (a relative `Rational`) and `stake` is the raw sum of `PerasVoteStake` values looked up from `PerasVoteStakeDistr`. [1](#0-0) 

The comment on `PerasVoteStake` explicitly states the problem:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake). … we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The call chain is:

1. An incoming `PerasVote` arrives via the `PerasVoteDiffusion` mini-protocol and is processed by `makePerasVotePoolWriterFromChainDB`.
2. `validatePerasVote` looks up the voter's stake from `PerasVoteStakeDistr` and assigns it **directly** to `vpvVoteStake` with no normalization.
3. `votesReachQuorum` sums all `vpvVoteStake` values via `mconcat` and calls `stakeAboveThreshold`.
4. `stakeAboveThreshold` compares the raw sum against the relative threshold `3/4`. [3](#0-2) [4](#0-3) 

The production network handler in `NodeToNode.hs` currently passes `pure (PerasVoteStakeDistr mempty)` as a temporary placeholder, with an explicit TODO noting that real ledger stake data must be wired in:

> "when actual plumbing for Peras is ready, we will have to extract the committee selection data from the chainDB to pass it here, instead of relying on an empty the stake distribution." [5](#0-4) 

Once real ledger stake data (absolute lovelace amounts, e.g., `1_000_000_000`) is wired in — as the TODO requires — the sum of even a single voter's absolute stake will be orders of magnitude larger than `3/4`, making `stakeAboveThreshold` return `True` for any single vote. The `mkPerasParams` default confirms the threshold is relative: [6](#0-5) 

The `makePerasVotePoolWriterFromChainDB` function, which is the production entry point, calls `validatePerasVote mkPerasParams sd vote` where `sd` will be the real stake distribution: [7](#0-6) 

---

### Impact Explanation

When real ledger stake data is wired in (as the TODO mandates), a single `PerasVote` from any voter with positive absolute stake will satisfy `stakeAboveThreshold`, causing `votesReachQuorum` to return a `ValidatedPerasVotesWithQuorum` and `forgePerasCert` to produce a `ValidatedPerasCert`. This certificate is then stored in the `ChainDB` and used to boost the targeted block's chain weight by `perasWeight = 15`. An unprivileged peer can therefore cause any honest node to accept an invalid Peras certificate for an arbitrary block, directly corrupting chain selection by artificially boosting a non-canonical chain. This is a bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The bug is latent in production code today and will become exploitable the moment the stake distribution plumbing is completed — a change that is explicitly planned and tracked. No key compromise, stake majority, or social engineering is required. Any peer that can send a `PerasVote` message via the `PerasVoteDiffusion` mini-protocol can trigger it.

---

### Recommendation

`stakeAboveThreshold` must normalize `PerasVoteStake` to a relative value before comparing it against `perasQuorumStakeThreshold`. The total stake of the committee (or the full `PerasVoteStakeDistr`) must be passed into `stakeAboveThreshold` so that the accumulated vote stake can be divided by the total, producing a value in `[0, 1]` comparable to the `3/4` threshold. Alternatively, `perasQuorumStakeThreshold` should be expressed in the same absolute units as the stake distribution. The fix must be applied before the stake distribution plumbing TODO is resolved.

---

### Proof of Concept

With the current empty-distribution placeholder replaced by a real ledger stake distribution where voter A holds `1_000_000_000` lovelace out of `10_000_000_000` total:

```
PerasVoteStakeDistr = { voterA -> PerasVoteStake (1_000_000_000 % 1) }
perasQuorumStakeThreshold = 3/4
```

A single vote from `voterA` produces:
```
totalVoteStake = PerasVoteStake (1_000_000_000 % 1)
stakeAboveThreshold: 1_000_000_000 >= 3/4 + 2/100  → True
```

`votesReachQuorum` returns `Just (ValidatedPerasVotesWithQuorum ...)` and a certificate is forged for the adversary's chosen block, despite `voterA` holding only 10% of total stake — far below the intended 75% quorum.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-176)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```
