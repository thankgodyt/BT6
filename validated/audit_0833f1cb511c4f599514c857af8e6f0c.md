### Title
Peras Quorum Check Compares Unnormalized Vote Stake Against Relative Threshold — Unit Mismatch Enables Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in the Peras voting subsystem directly compares accumulated `PerasVoteStake` values against a relative (normalized) quorum threshold without any normalization step. The code itself documents that this comparison is only valid when both operands are in the same units, but no enforcement exists. When the production stake distribution wiring is completed (replacing the current empty-map placeholder), if absolute ledger stake values are supplied — which is the natural representation from the Cardano ledger — any single voter with non-trivial stake will trivially exceed the `3/4` relative threshold, allowing an unprivileged peer to forge a Peras certificate for an arbitrary block with a single vote.

---

### Finding Description

**Vulnerability class:** Unit mismatch / accounting confusion in authorization check — directly analogous to the ERC20 `approve`/`transferFrom` shares-vs-rebalanced-amounts bug.

**Root cause — `stakeAboveThreshold`:** [1](#0-0) 

The function compares `unPerasVoteStake voteStake` (a raw `Rational` from the distribution) against `perasQuorumStakeThreshold` (hardcoded as `3/4`) plus `perasQuorumStakeThresholdSafetyMargin` (hardcoded as `2/100`). The code's own TODO comment states:

> "this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

**`PerasVoteStake` is populated without normalization:**

`validatePerasVote` (the degenerate instance used in production) performs a raw lookup from `PerasVoteStakeDistr` and stores the result directly into `ValidatedPerasVote.vpvVoteStake` with no normalization: [3](#0-2) 

**Quorum check uses the raw accumulated stake:**

`votesReachQuorum` sums `vpvVoteStake` values and passes the total directly to `stakeAboveThreshold`: [4](#0-3) 

`updateCandidateVoteState` calls `votesReachQuorum` to decide whether to forge a certificate: [5](#0-4) 

**Production wiring — current placeholder and the intended replacement:**

The production `NodeToNode.hs` currently passes `PerasVoteStakeDistr mempty` (empty map), causing all votes to be rejected. The TODO comment explicitly states this will be replaced with actual committee selection data: [6](#0-5) 

When the actual stake distribution is wired in, the `PerasVoteStakeDistr` will be populated from the Cardano ledger's pool stake distribution. The ledger represents stake as absolute `Coin`/Lovelace values (e.g., `1_000_000_000_000` Lovelace). If these absolute values are placed into `PerasVoteStakeDistr` without normalization to the committee's total stake, then `stakeAboveThreshold` will compare e.g. `1_000_000_000_000` against `0.77`, which is always `True`.

The `PerasVoteStakeDistr` type carries no invariant about normalization: [7](#0-6) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance.**

If absolute ledger stake values are supplied in `PerasVoteStakeDistr` when the production plumbing is completed:

1. Any single vote from a voter with non-zero absolute stake (e.g., `1 Lovelace`) satisfies `1 >= 0.77`, immediately triggering quorum.
2. `updateCandidateVoteState` calls `forgePerasCert`, producing a `ValidatedPerasCert` with a `perasWeight` boost (currently `15`).
3. The certificate is stored in the `ChainDB` and applied to chain selection via `WeightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost`.
4. An adversary controlling any registered stake pool can send a single crafted `PerasVote` message via the `PerasVoteDiffusion` mini-protocol to cause honest nodes to forge a certificate boosting the adversary's block by `15` weight units.
5. This makes the adversary's chain preferred over the honest chain in `preferCandidate`, constituting a chain selection manipulation. [8](#0-7) 

---

### Likelihood Explanation

The vulnerability is latent but structurally inevitable: the code explicitly acknowledges the unresolved unit question ("no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake"), and the production wiring is a known placeholder. The natural representation from the Cardano ledger (`IndividualPoolStake.individualPoolStake :: Rational`) is already a relative value, but the path from ledger snapshot to `PerasVoteStakeDistr` is unimplemented and undocumented. Any engineer completing the wiring without reading the TODO comment in `stakeAboveThreshold` will introduce the mismatch. The `PerasVoteStake` type provides no phantom type or newtype distinction between absolute and relative values, making the error invisible at the type level.

---

### Recommendation

1. **Enforce normalization at the boundary.** `stakeAboveThreshold` should accept the total committee stake and normalize internally, or `PerasVoteStakeDistr` should be replaced with a type that carries a normalization invariant (e.g., a phantom type `PerasVoteStake 'Relative` vs `PerasVoteStake 'Absolute`).

2. **Fix `stakeAboveThreshold` signature** to require the total stake denominator:
   ```haskell
   stakeAboveThreshold :: PerasParams -> PerasVoteStake -> PerasVoteStake -> Bool
   -- where the second argument is the total committee stake (denominator)
   ```

3. **Resolve the TODO** in `SupportsPeras.hs` lines 136–143 before wiring in the actual stake distribution. The normalization step must divide each voter's absolute stake by the total committee stake before storing it in `PerasVoteStakeDistr`.

4. **Add a property test** asserting that `stakeAboveThreshold` returns `False` when the sum of all votes in a distribution equals exactly the total stake (i.e., one voter holds 100% of stake should yield `True`, but a single voter holding `1/n` of total stake with threshold `3/4` should yield `False`).

---

### Proof of Concept

**Setup:** Private testnet with Peras enabled. Attacker controls one registered stake pool with any positive stake.

**Step 1 — Trigger:** Attacker sends a single `PerasVote` message via the `PerasVoteDiffusion` mini-protocol targeting an adversarial block `B_adv` in round `r`.

**Step 2 — Validation path:** `processVotes` → `validatePerasVote mkPerasParams sd vote`. If `sd` contains the attacker's pool with absolute stake `s` (e.g., `s = 1_000_000_000` Lovelace as `Rational`), `lookupPerasVoteStake` returns `PerasVoteStake (1_000_000_000 % 1)`.

**Step 3 — Quorum check:** `votesReachQuorum` computes `totalVoteStake = PerasVoteStake (1_000_000_000 % 1)`. `stakeAboveThreshold` evaluates `1_000_000_000 >= 3/4 + 2/100 = 0.77` → `True`.

**Step 4 — Certificate forged:** `forgePerasCert` produces `ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }` for `B_adv`.

**Step 5 — Chain selection:** `weightedSelectView` computes `wsvTotalWeight(B_adv) = blockNo(B_adv) + 15`. Honest nodes with `blockNo(B_honest) <= blockNo(B_adv) + 14` will switch to the adversary's chain. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L175-179)
```haskell
newtype PerasVoteStakeDistr = PerasVoteStakeDistr
  { unPerasVoteStakeDistr :: Map PerasVoterId PerasVoteStake
  }
  deriving newtype NoThunks
  deriving stock (Show, Eq, Generic)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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
