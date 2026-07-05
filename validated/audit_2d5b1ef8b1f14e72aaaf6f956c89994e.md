### Title
Peras Quorum Check Bypassed by Missing Vote-Stake Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a raw (potentially absolute) accumulated `PerasVoteStake` directly against a relative `perasQuorumStakeThreshold` without normalizing by total committee stake. The function's own TODO comment acknowledges the unit mismatch. When the production diffusion layer is wired to a real ledger-derived `PerasVoteStakeDistr` (replacing the current empty-map placeholder), any voter whose absolute stake exceeds the relative threshold value (e.g., 0.75 lovelace) trivially satisfies the quorum check alone, allowing a single-vote certificate to be forged for any block.

---

### Finding Description

`stakeAboveThreshold` is the sole gate that decides whether accumulated votes constitute a valid Peras quorum:

```haskell
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. ...
-- this function only makes sense when both values are relative (normalized)
-- values, so we should either normalize the 'PerasVoteStake' before calling
-- this function, or change this function to accept a stake distribution and
-- perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

`votesReachQuorum` feeds this function with a raw `mconcat` of individual `vpvVoteStake` values — no normalization by total committee stake occurs anywhere in the call chain:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [2](#0-1) 

Each individual `vpvVoteStake` is taken verbatim from `PerasVoteStakeDistr` via `lookupPerasVoteStake`: [3](#0-2) 

The `PerasVoteStake` type comment itself admits the representation is unresolved — "no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake": [4](#0-3) 

The production diffusion handler currently passes `PerasVoteStakeDistr mempty` as a placeholder, with an explicit TODO to replace it with real ledger-derived committee data:

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
(pure (PerasVoteStakeDistr mempty))
``` [5](#0-4) 

When that TODO is resolved and the distribution is populated with absolute lovelace values from the ledger (the natural representation), every voter whose absolute stake exceeds the relative threshold (e.g., any pool with > 0.75 lovelace) satisfies `stakeAboveThreshold` alone. The `updateCandidateVoteState` path then calls `forgePerasCert` and produces a `ValidatedPerasCert` for the adversary's chosen block: [6](#0-5) 

The `updateLoserVoteState` path also calls `stakeAboveThreshold` and would incorrectly flag a loser as above-quorum, triggering `RoundVoteStateLoserAboveQuorum` and corrupting the round vote state: [7](#0-6) 

The analog to the NounsDAO bug is exact: NounsDAO's `adjustedTotalSupply()` omitted unclaimed tokens from the denominator, making the quorum fraction too easy to satisfy. Here, `stakeAboveThreshold` omits the total-stake denominator entirely, making the quorum comparison dimensionally incoherent and trivially satisfiable with absolute values.

---

### Impact Explanation

A single crafted `PerasVote` from an unprivileged peer, once the real `PerasVoteStakeDistr` is wired in with absolute lovelace values, causes `votesReachQuorum` to return `Just` and `forgePerasCert` to produce a `ValidatedPerasCert` for any block the adversary names. That certificate is then stored in the `PerasVoteDB` / `ChainDB` and used to boost the adversary's chosen block with `perasWeight` in chain selection. Honest nodes following the boosted chain diverge from the canonical chain, constituting a **bypass of Peras certificate/vote verification** and a **chain-selection manipulation** reachable by an unprivileged peer via the vote-diffusion mini-protocol.

---

### Likelihood Explanation

**Medium.** The empty-map placeholder currently prevents exploitation in production. However, the TODO in `NodeToNode.hs` (line 402) explicitly schedules replacement with real ledger data. The ledger's natural representation of pool stake is absolute (lovelace / `Coin`), and the `PerasVoteStake` type carries no phantom unit tag to prevent absolute values from being stored. The `stakeAboveThreshold` TODO (lines 155–161) confirms the normalization gap is known but unresolved. Any developer wiring the real distribution without first reading and acting on both TODOs will introduce the exploitable condition.

---

### Recommendation

1. **Enforce units at the type level.** Introduce a `NormalizedPerasVoteStake` newtype (wrapping `Rational` in `[0,1]`) distinct from `PerasVoteStake`. Change `stakeAboveThreshold` and `votesReachQuorum` to accept only `NormalizedPerasVoteStake`.

2. **Normalize at the boundary.** Change `votesReachQuorum` (or the `validatePerasVote` call site) to accept the full `PerasVoteStakeDistr`, compute `totalStake = sum (Map.elems distr)`, and divide each `vpvVoteStake` by `totalStake` before summing and comparing to the threshold. This mirrors the fix recommended for NounsDAO: include the full denominator in the calculation.

3. **Guard the diffusion wiring.** When the `PerasVoteStakeDistr mempty` placeholder in `NodeToNode.hs` is replaced, add an assertion or type-level proof that the values stored are normalized fractions summing to ≤ 1.

---

### Proof of Concept

**Setup:** Peras is wired with `mkPerasParams` defaults. Suppose `perasQuorumStakeThreshold = 0.75` and `perasQuorumStakeThresholdSafetyMargin = 0.01`. The `PerasVoteStakeDistr` is populated with absolute lovelace: pool `P` has `1_000_000` lovelace.

**Step 1.** Adversary sends one `PerasVote` for block `B` from pool `P` over the vote-diffusion mini-protocol.

**Step 2.** `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams stakeDistr vote`. The degenerate instance looks up `P` in `stakeDistr` and returns `vpvVoteStake = PerasVoteStake 1_000_000`.

**Step 3.** `updateCandidateVoteState` calls `votesReachQuorum cfg [validatedVote]`:
- `totalVoteStake = mconcat [PerasVoteStake 1_000_000] = PerasVoteStake 1_000_000`
- `stakeAboveThreshold`: `1_000_000 >= 0.75 + 0.01` → **True**

**Step 4.** `forgePerasCert` is called and returns a `ValidatedPerasCert` for block `B` with `perasWeight`. The certificate is stored and used to boost `B` in chain selection.

**Result:** A single adversarial vote forges a valid Peras certificate for any block, bypassing the quorum requirement entirely.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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
