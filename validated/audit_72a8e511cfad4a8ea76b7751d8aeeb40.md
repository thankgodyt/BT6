### Title
Unit Mismatch in Peras Quorum Check Enables Certificate Bypass and Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares `PerasVoteStake` (a raw `Rational` sourced from the ledger's absolute lovelace distribution) against `PerasQuorumStakeThreshold` (a relative fraction, defaulting to `3/4`) without any normalization step. The code itself documents this as an unresolved unit mismatch. When absolute lovelace values are used as `PerasVoteStake`, the comparison is orders of magnitude off — any non-zero stake satisfies the quorum — allowing a single vote from an unprivileged peer to forge a Peras certificate for an arbitrary block and manipulate chain selection.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `stake = unPerasVoteStake voteStake` and `quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)`.

The default `PerasParams` sets `perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3/4)` and `perasQuorumStakeThresholdSafetyMargin = PerasQuorumStakeThresholdSafetyMargin (2/100)`, so the threshold is the relative value `0.77`.

The code carries an explicit, unresolved TODO directly above this function:

> *"this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."*

And the `PerasVoteStake` type comment states:

> *"At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee."*

`PerasVoteStake` is a plain `Rational` newtype with no enforced normalization. It is populated from `PerasVoteStakeDistr`, which maps voter IDs to their ledger stake — a distribution that naturally carries absolute lovelace values. The `lookupPerasVoteStake` function retrieves these values directly and they are stored in `ValidatedPerasVote.vpvVoteStake` without any normalization pass.

`stakeAboveThreshold` is called in three production paths:

1. `votesReachQuorum` → `updateCandidateVoteState` → `updatePerasRoundVoteStates` (certificate forging)
2. `updateLoserVoteState` (loser quorum guard)
3. The `PerasVoteDB` model used in storage-layer logic [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

When `PerasVoteStake` carries an absolute lovelace value (e.g., `1_000_000` for 1 ADA) and `PerasQuorumStakeThreshold` is the relative value `0.75`, the comparison `1_000_000 >= 0.77` is trivially true. This means:

- **Any single vote from any non-zero-stake peer immediately satisfies the quorum check.**
- `votesReachQuorum` returns `Just` after the very first vote, triggering `forgePerasCert`.
- The forged certificate boosts the voted block with `perasWeight = 15` in chain selection.
- An attacker with minimal stake can boost an adversarial or non-canonical block, causing honest nodes to prefer it over the canonical chain.

This is a bypass of the Peras certificate quorum check that enables unauthorized certificate acceptance and chain selection manipulation — matching the "Critical: bypass of Peras voting or certificate checks" impact class. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The normalization gap is explicitly documented as unresolved in production code. The `PerasVoteStakeDistr` is sourced from the ledger stake distribution, which uses absolute lovelace. No normalization step exists between the ledger distribution and `stakeAboveThreshold`. Any concrete `validatePerasVote` implementation that populates `vpvVoteStake` from the raw ledger distribution without dividing by total stake will trigger this condition. The likelihood is **high** given the acknowledged absence of the normalization and the natural tendency to use raw ledger values. [7](#0-6) 

---

### Recommendation

**Short term:** Enforce normalization before `stakeAboveThreshold` is called. Divide each voter's absolute lovelace stake by the total stake in the `PerasVoteStakeDistr` to produce a value in `[0, 1]` before storing it in `ValidatedPerasVote.vpvVoteStake`. Alternatively, change `stakeAboveThreshold` to accept the total stake and perform the division internally.

**Long term:** Introduce distinct newtypes for absolute stake (`AbsoluteStake`) and normalized stake (`RelativeStake`) so the type system prevents the two from being compared directly. Add property-based tests that verify quorum is not reached by a single voter holding less than the threshold fraction of total stake, across a range of total-stake magnitudes (analogous to the multi-decimal-precision fuzzing recommended in the original report).

---

### Proof of Concept

Assume a Cardano private testnet with total stake = `10_000_000_000_000` lovelace (10M ADA). An attacker controls a pool with `1_000_000` lovelace (1 ADA, 0.00001% of total stake).

1. Attacker's pool is in the `PerasVoteStakeDistr` with `PerasVoteStake { unPerasVoteStake = 1_000_000 % 1 }` (absolute lovelace, no normalization applied).
2. Attacker sends one `PerasVote` for an adversarial block `B_adv` in round `r`.
3. `validatePerasVote` creates `ValidatedPerasVote { vpvVoteStake = PerasVoteStake (1_000_000 % 1) }`.
4. `updatePerasRoundVoteStates` calls `updateCandidateVoteState`, which calls `votesReachQuorum`.
5. `stakeAboveThreshold params (PerasVoteStake (1_000_000 % 1))` evaluates:
   - `stake = 1_000_000`
   - `quorumThreshold + safetyMargin = 3/4 + 2/100 = 0.77`
   - `1_000_000 >= 0.77` → **True**
6. `forgePerasCert` is called; a certificate boosting `B_adv` with weight 15 is produced.
7. Honest nodes receiving this certificate apply the boost to `B_adv` in chain selection, preferring it over the canonical chain. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-272)
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
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-177)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L571-587)
```haskell
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Candidate ->
  Either
    (PerasForgeErr blk)
    (PerasVoteStateCandidateOrWinner blk)
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
