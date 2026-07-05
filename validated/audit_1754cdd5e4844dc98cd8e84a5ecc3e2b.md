### Title
Peras Quorum Check Assumes Normalized Vote Stake Without Enforcement - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares the accumulated `PerasVoteStake` directly against the quorum threshold without any normalization step, silently assuming both values are expressed in the same units (relative/normalized). This assumption is not enforced at the type level or at runtime. The code itself acknowledges the problem via an explicit TODO comment. If absolute ledger stake values are passed where normalized values are expected — a natural mistake given that the ledger natively provides absolute stake — the quorum check produces a meaningless result, either trivially granting or permanently denying Peras certificate formation.

### Finding Description

`stakeAboveThreshold` in `Ouroboros.Consensus.Block.SupportsPeras` performs the Peras quorum check by a bare numeric comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin  = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
``` [1](#0-0) 

The comment immediately above this function explicitly acknowledges the unit-mismatch risk:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units. That is, both are either absolute or relative (normalized) values. Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

`PerasVoteStake` is a plain `Rational` newtype with no unit annotation: [3](#0-2) 

The note on the type itself further confirms the ambiguity:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [4](#0-3) 

`stakeAboveThreshold` is called in two production code paths:

1. `votesReachQuorum` — the smart constructor that decides whether a set of votes forms a valid Peras certificate: [5](#0-4) 

2. `updateLoserVoteState` in the vote aggregation engine — which detects the error condition of a losing target going above quorum: [6](#0-5) 

The analog to the external report is direct: yVault hardcoded `1e18` instead of `decimals()`, assuming all tokens have 18 decimals. Here, `stakeAboveThreshold` hardcodes the assumption that `PerasVoteStake` is already normalized to the `[0,1]` range, matching the relative quorum threshold — but nothing in the type system or runtime enforces this.

### Impact Explanation

**If absolute ledger stake values (e.g., lovelace amounts) are stored in `PerasVoteStakeDistr` and passed through `validatePerasVote` without normalization:**

- The total accumulated `PerasVoteStake` for a round could be on the order of billions (total ADA supply in lovelace), while `perasQuorumStakeThreshold` is a small rational like `0.75`.
- The comparison `billions >= 0.75` is always `True` → **any single vote, or any small coalition, trivially reaches quorum** → invalid Peras certificates are forged and accepted.
- Conversely, if the stake distribution is normalized to per-voter fractions before the quorum threshold is scaled, the comparison could always be `False` → **Peras certificates can never be forged** → the Peras boosting mechanism is permanently disabled.

Either outcome breaks Peras certificate validation: the first allows unauthorized chain boosting (chain selection manipulation via illegitimate boosted blocks); the second silently disables the Peras security extension.

### Likelihood Explanation

The current implementation appears to use relative values consistently, which is why the bug has not yet manifested. However:

- There is **no type-level distinction** between absolute and relative `PerasVoteStake`.
- The ledger natively provides absolute stake, making it the natural value to store.
- The comment explicitly states the current behavior is an unresolved assumption, not a design guarantee.
- Any future implementation of `validatePerasVote` that populates `PerasVoteStakeDistr` directly from ledger stake without normalization — a natural and easy mistake — would activate the bug.
- The entry path is through network-received Peras votes processed by `validatePerasVote` → `votesReachQuorum` → `stakeAboveThreshold`.

### Recommendation

1. **Enforce units at the type level**: introduce distinct newtypes for absolute and normalized stake (e.g., `AbsoluteStake` vs `NormalizedStake`) so the compiler rejects mismatched comparisons.
2. **Normalize inside `stakeAboveThreshold`**: change the signature to accept the total stake distribution and divide `PerasVoteStake` by the total before comparing against the threshold.
3. **Normalize at the point of insertion**: ensure `validatePerasVote` always divides the voter's absolute ledger stake by the total committee stake before constructing `PerasVoteStake`.

### Proof of Concept

Suppose:
- `perasQuorumStakeThreshold = 3/4` (75 % of total stake, relative)
- `perasQuorumStakeThresholdSafetyMargin = 1/100`
- A single voter has absolute ledger stake of `1_000_000` lovelace, stored directly as `PerasVoteStake (1000000 % 1)`

Then `stakeAboveThreshold` evaluates:

```
1000000 >= (3/4) + (1/100)   -- True, trivially
```

A single vote from any voter with non-zero stake would cause `votesReachQuorum` to return `Just`, forging a Peras certificate for that voter's chosen block, regardless of whether the honest majority actually voted for it. This allows an unprivileged peer to boost an arbitrary block on the chain by submitting a single crafted vote.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L144-151)
```haskell
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
  deriving stock Generic
  deriving Show via Quiet PerasVoteStake
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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
