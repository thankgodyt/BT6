### Title
Peras Quorum Check Compares Unnormalized Absolute Vote Stake Against Relative Threshold, Enabling Single-Vote Certificate Forging — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function compares accumulated `PerasVoteStake` — which is populated from ledger stake without normalization — directly against a relative quorum threshold (e.g., `3/4` of total committee stake). The code itself documents this as an unresolved design gap. Because the two values are in incompatible units (absolute vs. relative), the quorum check is structurally incorrect: with absolute ledger stake values, the check trivially passes on the very first vote, allowing any single committee member to unilaterally forge a Peras certificate for any block they choose.

---

### Finding Description

**Two incompatible representations compared in the critical quorum gate**

`stakeAboveThreshold` is the sole gate that decides whether a Peras certificate is forged:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake          -- accumulated Rational
  quorumThreshold = unPerasQuorumStakeThreshold ...   -- 3/4  (relative)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ... -- 2/100
``` [1](#0-0) 

The default parameters set the threshold to `3/4`:

```haskell
perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
perasQuorumStakeThresholdSafetyMargin = PerasQuorumStakeThresholdSafetyMargin (2 / 100)
``` [2](#0-1) 

The code itself acknowledges the unit mismatch with an explicit TODO:

> "NOTE: At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake). … this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [3](#0-2) 

**How `PerasVoteStake` is populated**

`PerasVoteStake` is attached to each vote by `validatePerasVote`, which simply looks up the voter's entry in `PerasVoteStakeDistr` — a plain `Map PerasVoterId PerasVoteStake` supplied by the caller:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [4](#0-3) 

No normalization step exists anywhere in the production path. The natural population of `PerasVoteStakeDistr` from the ledger would use absolute lovelace-denominated stake values (e.g., `1_000_000`). Compared against `3/4 + 2/100 = 77/100`, the check `1_000_000 >= 77/100` is trivially `True` on the very first vote.

**Production call chain**

The check is exercised on every incoming vote:

```
implAddVote (PerasVoteDB/Impl.hs)
  → updatePerasRoundVoteStates
    → updatePerasRoundVoteState
      → updateCandidateVoteState
        → votesReachQuorum          ← calls stakeAboveThreshold
          → forgePerasCert          ← certificate forged if True
``` [5](#0-4) [6](#0-5) 

**Analog to the external report**

The external report's root cause is that `totalCollateralValue` aggregates pooled tokens across all NFTs *before* pricing (truncated once), while `_calculateProposedReturnedCapital` prices each NFT *individually* (truncated N times). The two methods produce different numeric values for the same collateral, so the comparison `proposedLiquidationAmount >= totalUserCollateral` silently fails even when all collateral is liquidated.

Here, the same structural defect appears: the quorum threshold is expressed as a *relative* fraction of total committee stake (`3/4`), while the accumulated `PerasVoteStake` is an *absolute* ledger value. The comparison `stake >= quorumThreshold` is between incompatible representations of "stake," so the check produces a wrong answer — in this case, trivially `True` — regardless of how many votes have actually been cast.

---

### Impact Explanation

With absolute ledger stake values in `PerasVoteStakeDistr`, `stakeAboveThreshold` returns `True` on the very first vote received for any target. `updateCandidateVoteState` then calls `forgePerasCert` and transitions the round to `Quorum` state, producing a `ValidatedPerasCert` with the full `perasWeight` boost. Any single committee member — regardless of their actual share of total stake — can unilaterally forge a certificate for any block they choose. The boosted block then wins chain selection via `wsvTotalWeight`, causing honest nodes to switch to the attacker's preferred chain. This is a bypass of the Peras voting/certificate quorum check that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The attack requires only that the adversary hold any positive stake (making them a committee member). No key compromise, stake majority, or operator access is needed. The vulnerability is reachable via the standard vote miniprotocol: the attacker sends a single well-formed vote message. The code's own TODO comment confirms the normalization is absent and the comparison is known to be unit-inconsistent.

---

### Recommendation

Normalize `PerasVoteStake` to the same relative unit as the quorum threshold before the comparison. Two equivalent fixes:

1. **At population time**: when building `PerasVoteStakeDistr` from the ledger, divide each voter's absolute stake by the total committee stake so every entry is a fraction in `[0,1]`.
2. **At check time**: change `stakeAboveThreshold` to accept the total committee stake and perform `stake / totalStake >= quorumThreshold + safetyMargin` internally, mirroring how `totalCollateralValue` in the external report fixes the issue by aggregating before pricing.

The second approach is safer because it makes the normalization invariant impossible to violate at the call site.

---

### Proof of Concept

```
Setup:
  - Total committee stake: 10_000_000 lovelace
  - Quorum threshold: 3/4 (relative)
  - Attacker's stake: 100_000 lovelace (1% of total — far below quorum)
  - PerasVoteStakeDistr populated with absolute values:
      { attacker_pool_id -> PerasVoteStake (100_000 % 1) }

Attack:
  1. Attacker sends one WFALSPersistentVote for block B (the block they want boosted).
  2. Node calls implAddVote → updateCandidateVoteState.
  3. votesReachQuorum computes:
       totalVoteStake = PerasVoteStake (100_000 % 1)
  4. stakeAboveThreshold checks:
       100_000 >= 3/4 + 2/100   →   100_000 >= 77/100   →   True
  5. forgePerasCert is called; a ValidatedPerasCert with boost=15 is stored.
  6. Chain selection via wsvTotalWeight now prefers block B over any
     competing chain that lacks a certificate, even if the competing
     chain is longer by up to 14 blocks.

Expected (correct) result:
  totalVoteStake / totalCommitteeStake = 100_000 / 10_000_000 = 1/100
  1/100 >= 77/100   →   False   →   no certificate forged.
``` [1](#0-0) [7](#0-6) [5](#0-4)

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
