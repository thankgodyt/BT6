### Title
Peras Quorum Check Assumes Normalized Vote Stake Without Enforcing Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in the Peras protocol extension compares accumulated `PerasVoteStake` values directly against a hardcoded relative quorum threshold (`3/4`) without enforcing that the vote stake values are normalized (relative fractions of total committee stake). The code itself documents this assumption as unresolved. If `PerasVoteStakeDistr` is populated with absolute ledger stake values — the natural representation from the Cardano ledger — any voter whose absolute stake exceeds `3/4` (trivially true for any real stake pool holding lovelace) would reach quorum alone with a single vote, causing a fraudulent Peras certificate to be forged and accepted, and giving an adversarially-chosen block a weight boost of 15 in chain selection.

---

### Finding Description

In `stakeAboveThreshold`, the total accumulated `PerasVoteStake` is compared directly to the hardcoded relative threshold `3/4` plus a safety margin `2/100`:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The code explicitly documents that this comparison is only meaningful if both operands are in the same units (both relative/normalized), but does **not** enforce this:

```
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
``` [2](#0-1) 

The `PerasVoteStake` type is a bare `Rational` with no unit enforcement: [3](#0-2) 

The quorum threshold is hardcoded in `mkPerasParams` as `3/4` (relative): [4](#0-3) 

The `validatePerasVote` function (the degenerate production instance) assigns the stake value directly from `PerasVoteStakeDistr` without any normalization step: [5](#0-4) 

The `votesReachQuorum` function — the smart constructor that gates certificate forging — calls `stakeAboveThreshold` on the raw accumulated stake: [6](#0-5) 

This is the same root cause as the external report: a hardcoded fixed assumption about the unit/scale of an external value (`1 Stable = 1 USD` → `PerasVoteStake = normalized fraction`) that is not enforced at the comparison site.

Additionally, the production certificate ingestion path (`makePerasCertPoolWriterFromChainDB`) calls `validatePerasCert mkPerasParams`, which in the degenerate instance unconditionally returns `Right` for every certificate received from a peer: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**Impact: High** — Chain selection bug.

If `PerasVoteStakeDistr` is populated with absolute ledger stake values (e.g., lovelace amounts in the range of millions), then any voter's absolute stake trivially exceeds the relative threshold `3/4 + 2/100 = 0.77`. A single vote from any stake pool would immediately satisfy `stakeAboveThreshold`, causing `votesReachQuorum` to return `Just`, which triggers `forgePerasCert` and produces a `ValidatedPerasCert` with `vpcCertBoost = perasWeight params = 15`.

This certificate is then stored in `PerasCertDB` and used by `implGetWeightSnapshot` to compute `PerasWeightSnapshot`, which feeds into `WeightedSelectView` chain comparison: [9](#0-8) 

A block boosted by 15 weight units would be preferred over 15 unboosted blocks of equal block number, allowing an adversary to make an honest node prefer a non-canonical chain. This matches the **High** impact category: "Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

---

### Likelihood Explanation

**Likelihood: Medium.**

The bug is latent and depends on how `PerasVoteStakeDistr` is populated by the caller of `validatePerasVote`. The code explicitly documents that the normalization is unresolved ("no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake"). If the distribution is populated with absolute lovelace values (the natural ledger representation), the bug is immediately exploitable. The production certificate ingestion path already uses the degenerate `validatePerasCert` that accepts all certificates unconditionally, compounding the exposure. The Peras protocol is under active development and the code is in production source paths (`src/ouroboros-consensus`).

---

### Recommendation

1. **Enforce normalization at the boundary**: `stakeAboveThreshold` should either accept a total-stake parameter and normalize internally, or the type system should distinguish `AbsoluteStake` from `RelativeStake` to prevent unit confusion at compile time.
2. **Implement `validatePerasCert`**: The degenerate instance that unconditionally returns `Right` must be replaced with actual cryptographic and quorum verification before Peras certificates are accepted from untrusted peers.
3. **Normalize `PerasVoteStakeDistr` at construction**: Wherever `PerasVoteStakeDistr` is built from ledger state, divide each voter's absolute stake by the total committee stake before storing it, so that `PerasVoteStake` values are always in `[0, 1]` and comparable to the relative threshold.

---

### Proof of Concept

**Setup**: A private testnet with Peras enabled. Attacker controls one stake pool with any positive lovelace stake (e.g., 1,000,000 lovelace).

**Attack sequence**:

1. Attacker's node sends a `PerasVote` for an adversarial block `B_adv` in round `r` to an honest node.
2. The honest node calls `validatePerasVote _params stakeDistr vote`. The attacker's voter ID is in `stakeDistr` with absolute stake `1_000_000` (as a `Rational`).
3. `ValidatedPerasVote { vpvVoteStake = PerasVoteStake (1000000 % 1) }` is returned.
4. `votesReachQuorum` calls `stakeAboveThreshold params (PerasVoteStake (1000000 % 1))`.
5. The check `1000000 >= 3/4 + 2/100 = 0.77` is `True`.
6. `forgePerasCert` is called, producing `ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }` for `B_adv`.
7. The certificate is stored and `PerasWeightSnapshot` is updated.
8. Chain selection now computes `wsvTotalWeight` for any chain containing `B_adv` as `BlockNo(B_adv) + 15`, making it preferred over 15 honest blocks of equal height.
9. The honest node switches to the adversarial chain. [1](#0-0) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
