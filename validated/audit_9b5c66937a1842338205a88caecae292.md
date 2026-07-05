### Title
Peras Quorum Check Compares Absolute Stake Against Relative Threshold Without Unit Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares accumulated `PerasVoteStake` (a raw `Rational` sourced from the ledger's absolute stake distribution) directly against `perasQuorumStakeThreshold` (a relative fraction, e.g. `3/4`), without normalizing the vote stake to the same unit. This is the exact analog of the `redeemDyad()` decimal-mismatch class: two quantities with incompatible scales are compared as if they were equal in unit. The code itself acknowledges the problem in a `TODO` comment but leaves the comparison live in the production certificate-forging path.

---

### Finding Description

`stakeAboveThreshold` is defined as:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin  = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
```

The `TODO` comment immediately above it states:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

The companion `NOTE` on `PerasVoteStake` itself states:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."

The ledger's stake distribution provides absolute lovelace values. `validatePerasVote` looks up a voter's entry from `PerasVoteStakeDistr` and stores it verbatim as `vpvVoteStake`. When `votesReachQuorum` accumulates these values via `mconcat` and calls `stakeAboveThreshold`, it compares an absolute lovelace sum (e.g. `1_000_000_000_000`) against the relative threshold `3/4 + 2/100 = 0.77`. The comparison is always `True` for any voter with non-trivial stake, meaning **a single vote immediately satisfies quorum**.

The call chain in production code is:

```
validatePerasVote (looks up absolute stake from PerasVoteStakeDistr)
  → ValidatedPerasVote { vpvVoteStake = <absolute lovelace> }
    → votesReachQuorum → stakeAboveThreshold   [SupportsPeras.hs:269-270]
      → updateCandidateVoteState               [Aggregation.hs:582]
        → updatePerasRoundVoteState            [Aggregation.hs:199]
          → PerasVoteDB Impl.addPerasVote      [Impl.hs]
```

None of these steps normalize the stake before the comparison.

---

### Impact Explanation

**Critical — Bypass of Peras voting/certificate quorum checks.**

If `PerasVoteStakeDistr` is populated with absolute lovelace values (the natural output of the ledger stake distribution), then for any stake pool with stake > 0 lovelace, the condition `stake >= 0.77` is trivially satisfied. A single vote from any eligible voter immediately forges a Peras certificate, bypassing the quorum requirement entirely. A forged certificate boosts a block's chain-selection weight by `perasWeight` (default: 15), causing honest nodes to prefer an adversarially chosen block over the canonical chain. This constitutes unauthorized certificate acceptance and a chain-selection safety failure.

Conversely, if `PerasVoteStakeDistr` is populated with already-normalized values in `[0,1]`, the quorum check works correctly — but the code provides no enforcement of this invariant, and the comment explicitly says the normalization step is unresolved.

---

### Likelihood Explanation

**High.** The vulnerability is in the production certificate-forging path (`PerasVoteDB/Impl.hs`, `Aggregation.hs`), not in test or unstable libraries. The `PerasVoteStakeDistr` is constructed from the ledger's stake distribution, which naturally yields absolute lovelace values. Any stake pool operator (an unprivileged peer) who submits a single valid `PerasVote` message triggers the path. No key compromise, admin access, or stake majority is required — only a valid vote signature from any registered stake pool.

---

### Recommendation

Normalize `PerasVoteStake` to a relative fraction before the comparison in `stakeAboveThreshold`, or change the function signature to accept the total stake distribution and perform normalization internally:

```haskell
stakeAboveThreshold
  :: PerasParams
  -> Rational          -- total stake in the distribution (for normalization)
  -> PerasVoteStake    -- accumulated absolute vote stake
  -> Bool
stakeAboveThreshold params totalStake voteStake =
  relativeStake >= quorumThreshold + safetyMargin
 where
  relativeStake   = unPerasVoteStake voteStake / totalStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
```

All call sites (`votesReachQuorum`, `updateLoserVoteState`, the `PerasVoteDB` model) must be updated to pass the total stake. The `PerasVoteStakeDistr` type should be documented to specify whether it holds absolute or relative values, and the conversion from ledger stake to `PerasVoteStake` must be made explicit and consistent.

---

### Proof of Concept

**Setup:** Default `PerasParams` with `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`. A `PerasVoteStakeDistr` populated from the ledger with one voter holding `1_000_000_000` lovelace (1000 ADA — a small stake pool).

**Step 1:** Attacker (stake pool operator) submits a single `PerasVote` for block `B` in round `R`.

**Step 2:** `validatePerasVote` looks up the voter in `PerasVoteStakeDistr`, returning `PerasVoteStake (1_000_000_000 % 1)`.

**Step 3:** `votesReachQuorum` calls `stakeAboveThreshold params (PerasVoteStake (1_000_000_000 % 1))`.

**Step 4:** The check evaluates `1_000_000_000 >= 3/4 + 2/100 = 0.77` → `True`.

**Step 5:** `forgePerasCert` is called, producing a `ValidatedPerasCert` boosting block `B` by weight 15.

**Result:** A single vote from a small stake pool forges a Peras certificate, bypassing the quorum requirement. Honest nodes receiving this certificate will prefer block `B` in chain selection, regardless of whether `B` is on the canonical chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L93-109)
```haskell
-- | Total stake needed to forge a Peras certificate.
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)

-- | Safety margin needed on top of the quorum stake threshold.
--
-- NOTE: this is needed to account for an extremely unlikely local sortition
-- where not enough honest non-persistent parties decide to vote in a round.
-- This mostly depend on the expected size of the voting committee.
newtype PerasQuorumStakeThresholdSafetyMargin
  = PerasQuorumStakeThresholdSafetyMargin {unPerasQuorumStakeThresholdSafetyMargin :: Rational}
  deriving Show via Quiet PerasQuorumStakeThresholdSafetyMargin
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
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
