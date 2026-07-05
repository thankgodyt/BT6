### Title
`mkPerasParams` Hardcodes Peras Protocol Parameters Independent of Genesis Configuration, Breaking Chain Selection and Rollback Guarantees When Peras Is Enabled — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs`)

---

### Summary

`mkPerasParams` is a zero-argument function that returns a `PerasParams` bundle with every field hardcoded to mainnet-calibrated constants (e.g., `perasWeight = 15`, `perasRoundLength = 90`, `perasQuorumStakeThreshold = 3/4`). The code itself acknowledges this is wrong: `"NOTE: in the future this will depend on a concrete 'BlockConfig'."` These hardcoded values are wired directly into the production ChainDB initialisation path and the live vote-diffusion path. When Peras is enabled on any network whose genesis parameters differ from the assumed mainnet values, the weight-based chain selection and rollback-boundary logic operate on incorrect weights, allowing an unprivileged peer's crafted certificate to make blocks immutable prematurely or to cause a node to prefer a non-canonical chain.

---

### Finding Description

`mkPerasParams` is defined as a pure constant:

```haskell
mkPerasParams :: PerasParams
mkPerasParams = PerasParams
  { perasWeight = PerasWeight 15
  , perasRoundLength = PerasRoundLength 90
  , perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
  , perasIgnoranceRounds = PerasIgnoranceRounds 487
  , perasCooldownRounds  = PerasCooldownRounds  1928
  , ...
  }
``` [1](#0-0) 

These constants are calibrated for mainnet (k = 2160, f = 0.05, slot = 1 s). The code comment explicitly acknowledges the dependency on `BlockConfig` is missing.

`mkPerasParams` is injected into the production ChainDB at `completeChainDbArgs`:

```haskell
PerasVoteDB.pvdbaPerasCfg = mkPerasParams
``` [2](#0-1) 

It is also used directly in the live vote-diffusion writers for both the isolated `PerasVoteDB` path and the full `ChainDB` path:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) [4](#0-3) 

When a certificate is validated, it receives a boost equal to `perasWeight params`:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [5](#0-4) 

This boost feeds directly into `totalWeightOfFragment`, which drives chain selection:

```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
``` [6](#0-5) 

And into `takeVolatileSuffix`, which determines the immutable/volatile boundary using `maxRollbackWeight k`:

```haskell
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap = AF.anchorNewest (unPerasWeight k)
  | otherwise = takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where k = maxRollbackWeight secParam
``` [7](#0-6) 

The `SecurityParam` is reinterpreted as a weight bound in Peras:

```haskell
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14.
``` [8](#0-7) 

The invariant requires `perasWeight < k` for the security guarantee to hold. With `perasWeight` hardcoded to 15, any network with `k ≤ 15` (a private testnet is explicitly in scope per the prompt) will have a single certificate-boosted block whose weight exceeds `k`, making it immediately immutable and preventing any rollback past it — even when the canonical chain requires one.

---

### Impact Explanation

**Chain selection / rollback boundary corruption (High).**

When Peras is enabled (`rnFeatureFlags`) on a network where `k ≤ 15` (e.g., a private testnet or a future network with adjusted parameters), a single Peras certificate with the hardcoded `perasWeight = 15` gives a block a weight that equals or exceeds `k`. `takeVolatileSuffix` will then anchor the volatile suffix *before* that block, making it permanently immutable from the node's perspective. If the honest majority later requires rolling back past that block (e.g., due to a fork), the node cannot do so and diverges from the canonical chain — a consensus safety failure.

Additionally, the hardcoded `perasQuorumStakeThreshold = 3/4` is used in `stakeAboveThreshold` during vote aggregation. On a network where the intended quorum is different, this allows certificates to be forged (or suppressed) incorrectly, enabling an adversary with sufficient stake to manufacture a certificate that boosts a non-canonical block and triggers the above chain-selection divergence.

---

### Likelihood Explanation

Peras is currently gated behind `rnFeatureFlags` and disabled by default. However:

1. The code is already wired into the production `completeChainDbArgs` path — enabling the flag is sufficient to activate the bug.
2. Private testnets and pre-production deployments routinely use smaller `k` values (e.g., k = 10 or k = 5) to accelerate testing. The prompt explicitly lists "private-testnet sequence" as a valid entry path.
3. The bug is self-documenting: the code comment says the values *should* depend on `BlockConfig` but do not, confirming the mismatch is known and unresolved.
4. An unprivileged peer needs only to send valid-looking Peras votes; no key compromise or admin access is required.

---

### Recommendation

`mkPerasParams` must accept the relevant genesis/block-config parameters and derive its fields from them, analogously to how `mkTPraosParams` derives its fields from `SL.ShelleyGenesis`:

```haskell
mkPerasParams :: SecurityParam -> Rational -> SlotLength -> PerasParams
mkPerasParams secParam activeSlotCoeff slotLen = PerasParams
  { perasWeight = deriveWeight secParam activeSlotCoeff
  , perasRoundLength = deriveRoundLength slotLen activeSlotCoeff
  , perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
  , ...
  }
```

`completeChainDbArgs` and both `makePerasVotePoolWriter*` functions must be updated to pass the actual `TopLevelConfig`-derived parameters instead of calling the zero-argument `mkPerasParams`. The invariant `perasWeight < k` must be enforced at construction time with an assertion or type-level constraint.

---

### Proof of Concept

Configure a private testnet with Peras enabled and `k = 10` (a common testnet value). Observe:

1. A peer sends enough Peras votes for a block `B` to reach quorum (using the hardcoded `perasQuorumStakeThreshold = 3/4`).
2. A certificate is forged with `vpcCertBoost = PerasWeight 15`.
3. `takeVolatileSuffix` is called with `maxRollbackWeight (SecurityParam 10) = PerasWeight 10`.
4. `totalWeightOfFragment` for any suffix containing `B` returns at least `PerasWeight 16` (1 for the block + 15 boost).
5. Since `16 > 10`, `B` is placed in the immutable prefix immediately.
6. A competing honest chain that forks before `B` arrives; the node cannot switch to it because `forksAtMostKWeight` returns `False` — the fork depth in weight exceeds `k`.
7. The node is permanently stuck on the adversarially-boosted chain, diverging from the honest majority. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L134-177)
```haskell
-- | Instantiate default Peras protocol parameters.
--
-- NOTE: in the future this will depend on a concrete 'BlockConfig'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs (L229-233)
```haskell
      , cdbPerasVoteDbArgs =
          PerasVoteDB.PerasVoteDbArgs
            { PerasVoteDB.pvdbaTracer = PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
            , PerasVoteDB.pvdbaPerasCfg = mkPerasParams
            }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-112)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-142)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L313-317)
```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L369-377)
```haskell
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-37)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L70-89)
```haskell
forksAtMostKWeight ::
  ( StandardHash blk
  , HasHeader b
  , HeaderHash blk ~ HeaderHash b
  ) =>
  PerasWeightSnapshot blk ->
  -- | By how much weight can we roll back our chain at most?
  PerasWeight ->
  -- | Our chain @ours@.
  AnchoredFragment b ->
  -- | Their chain @theirs@.
  AnchoredFragment b ->
  -- | Indicates whether their chain forks at most the given the amount of
  -- weight. Returns 'False' if the two fragments do not intersect.
  Bool
forksAtMostKWeight weights maxWeight ours theirs =
  case ours `AF.intersect` theirs of
    Nothing -> False
    Just (_, _, ourSuffix, _) ->
      totalWeightOfFragment weights ourSuffix <= maxWeight
```
