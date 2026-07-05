### Title
Peras Quorum Check Compares Unnormalized `PerasVoteStake` Against Relative Threshold Without Scaling — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares a `PerasVoteStake` value (which may carry absolute ledger stake in lovelace) against `perasQuorumStakeThreshold` (a relative value of `3/4`). The code itself acknowledges the unit mismatch in a TODO comment but does not enforce normalization. When the production plumbing that populates `PerasVoteStakeDistr` from the ledger is wired in, a single vote from any voter with ≥ 1 lovelace of stake would satisfy the quorum check, allowing an unprivileged peer to trigger certificate forging with a single vote.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the quorum check:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `quorumThreshold = 3/4` and `safetyMargin = 2/100` (both relative, in `[0,1]`). [1](#0-0) 

The `PerasVoteStake` type is a bare `Rational` with no enforced unit: [2](#0-1) 

The code comment on `stakeAboveThreshold` explicitly acknowledges the mismatch:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [3](#0-2) 

The `validatePerasVote` implementation (the degenerate `BlockSupportsPeras` instance) assigns the raw value from `PerasVoteStakeDistr` directly to `vpvVoteStake` with no normalization step: [4](#0-3) 

`stakeAboveThreshold` is called in two places in the production vote-aggregation path:

1. `votesReachQuorum` (line 270), which is called from `updateCandidateVoteState` (line 582 of `Aggregation.hs`).
2. `updateLoserVoteState` (line 603 of `Aggregation.hs`). [5](#0-4) [6](#0-5) 

Both are reached from `updatePerasRoundVoteStates`, which is called from `implAddVote` in the production `PerasVoteDB`: [7](#0-6) 

The production diffusion handler currently passes `pure (PerasVoteStakeDistr mempty)` as a placeholder, with an explicit TODO to replace it with real ledger data: [8](#0-7) 

When that placeholder is replaced with actual ledger stake values (absolute lovelace amounts), the comparison `stake >= 3/4` will be evaluated against values that are orders of magnitude larger than 1, making the condition trivially true for any voter with ≥ 1 lovelace.

The default parameters confirm the threshold is relative: [9](#0-8) 

---

### Impact Explanation

When `PerasVoteStakeDistr` is populated with absolute ledger stakes (the natural representation from the Cardano ledger, where stake is measured in lovelace), any voter with ≥ 1 lovelace produces a `PerasVoteStake` of at least `1`, which satisfies `1 >= 3/4 + 2/100`. A single vote from any such voter would cause `votesReachQuorum` to return `Just`, triggering `forgePerasCert` and producing a `ValidatedPerasCert`. This is a complete bypass of the Peras quorum requirement: a certificate can be forged with a single vote instead of requiring ≥ 3/4 of total committee stake. The forged certificate carries a `PerasWeight` boost that influences chain selection, allowing an attacker to boost an arbitrary block and manipulate the preferred chain.

---

### Likelihood Explanation

The bug is latent today because the production code uses an empty `PerasVoteStakeDistr`. However, the TODO comment in `NodeToNode.hs` explicitly states this will be replaced with real committee selection data. The unit mismatch is not caught by the type system (both sides are `Rational`), and the TODO comment on `stakeAboveThreshold` itself shows the developers are aware of the ambiguity but have not resolved it. Any developer wiring in the ledger stake distribution in the natural way (absolute lovelace values) will trigger the bug without any additional attacker action beyond submitting a single valid vote.

---

### Recommendation

1. Enforce normalization at the boundary where `PerasVoteStakeDistr` is constructed from ledger data. Divide each voter's absolute stake by the total stake of the committee before storing it as `PerasVoteStake`.
2. Alternatively, change `stakeAboveThreshold` to accept the total committee stake and perform the normalization internally, making the unit contract explicit and compiler-checked.
3. Consider introducing a `NormalizedPerasVoteStake` newtype (distinct from `PerasVoteStake`) to make the unit invariant enforced by the type system, preventing future callers from accidentally passing absolute values.

---

### Proof of Concept

**Setup:** Wire `PerasVoteStakeDistr` with a single entry mapping voter `V` to `PerasVoteStake (1_000_000_000 % 1)` (1 billion lovelace = 1000 ADA, a realistic stake pool stake).

**Step 1:** Peer submits one `PerasVote` from voter `V` for block `B` in round `R`.

**Step 2:** `validatePerasVote mkPerasParams stakeDistr vote` succeeds, returning `Right (ValidatedPerasVote { vpvVoteStake = PerasVoteStake (1_000_000_000 % 1) })`.

**Step 3:** `updatePerasRoundVoteStates` is called. Inside `updateCandidateVoteState`, `votesReachQuorum cfg [vote]` is called.

**Step 4:** `stakeAboveThreshold params (PerasVoteStake (1_000_000_000 % 1))` evaluates:
```
1_000_000_000 >= 3/4 + 2/100  →  True
```

**Step 5:** `forgePerasCert cfg votesWithQuorum` is called and returns a `ValidatedPerasCert` boosting block `B` with `PerasWeight 15`.

**Result:** A certificate is forged from a single vote, bypassing the 3/4 quorum requirement. The boosted block gains a chain-selection advantage of 15 blocks, potentially causing honest nodes to prefer the attacker's chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
