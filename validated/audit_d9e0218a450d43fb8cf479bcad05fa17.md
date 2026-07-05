### Title
`PerasWeight` Accumulation via `Sum Word64` Silently Overflows in Chain Selection and Immutable-Boundary Computation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs`)

---

### Summary

`PerasWeight` is a `newtype` over `Word64` whose `Semigroup`/`Monoid` instances are derived via `Sum Word64`, which uses plain modular (`+`) arithmetic with no overflow check. Every accumulation of Peras boost weights — in `weightBoostOfFragment`, `totalWeightOfFragment`, and `wsvTotalWeight` — silently wraps on overflow. These values are the sole inputs to Peras chain selection (`preferCandidate`) and the immutable-boundary calculation (`takeVolatileSuffix`). A sufficiently large accumulated boost causes the computed total weight to wrap to a small value, making a heavier chain appear lighter and corrupting both chain selection and the rollback-safety boundary.

---

### Finding Description

**Root cause — `PerasWeight` Semigroup instance:**

`PerasWeight` is defined in `Params.hs` as:

```haskell
newtype PerasWeight = PerasWeight {unPerasWeight :: Word64}
deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
```

`Sum Word64` resolves `(<>)` to `(+) @Word64`, which is modular arithmetic in GHC — it wraps silently on overflow with no exception or error. [1](#0-0) 

**Overflow site 1 — `weightBoostOfFragment` (unchecked `foldMap`):**

```haskell
foldMap
  (weightBoostOfPoint weightSnap . castPoint . blockPoint)
  (AF.toOldestFirst frag)
```

`foldMap` accumulates via `(<>)` — i.e., `Sum Word64` addition — across every block on the fragment. No overflow guard exists. [2](#0-1) 

**Overflow site 2 — `totalWeightOfFragment` (unchecked `<>`):**

```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost  = weightBoostOfFragment weightSnap frag
```

Both operands are `Word64`-backed; their sum is unchecked. [3](#0-2) 

**Overflow site 3 — `wsvTotalWeight` (unchecked `BlockNo + PerasWeight`):**

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

`BlockNo` is `Word64`; `wsvWeightBoost` is `PerasWeight` (`Word64`). Their sum is unchecked. [4](#0-3) 

**Overflow site 4 — `addToPerasWeightSnapshot` (unchecked per-point accumulation):**

```haskell
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```

Multiple certificates boosting the same block accumulate via `(<>)` with no overflow check. [5](#0-4) 

**Contrast with the existing overflow guard for `ByteSize32`:**

The same codebase explicitly acknowledges the `Sum Word64` overflow hazard for `ByteSize32` and adds a guard in `pureTryAddTx`:

> *"This is modular arithmetic, so uses need to be concerned with overflow … WARNING: anywhere this type occurs is a very strong indicator that overflow will break assumptions, so overflow must therefore be guarded against."*

No equivalent guard exists anywhere in the `PerasWeight` chain-selection path. [6](#0-5) [7](#0-6) 

---

### Impact Explanation

**Chain selection corruption.** `preferCandidate` in `SelectView.hs` compares `wsvTotalWeight ours` against `wsvTotalWeight cand`. If the candidate's accumulated boost overflows to a small value, the node concludes `ours > cand` and rejects the heavier chain, permanently preferring a non-canonical fork. [8](#0-7) 

**Immutable-boundary miscalculation.** `takeVolatileSuffix` uses `totalWeightOfFragment snap` to determine which blocks are buried under weight `k` and therefore immutable. If the total weight overflows to a small value, the function returns a longer volatile suffix than it should, treating blocks that are actually immutable as rollback-eligible. This violates the `k`-deep safety guarantee. [9](#0-8) 

---

### Likelihood Explanation

With the current default `perasWeight = 15` and `k = 2160`, the maximum realistic accumulated weight per fragment is on the order of tens of thousands — far below `Word64.maxBound ≈ 1.8 × 10^19`. Overflow is not reachable under current mainnet parameters.

However, the structural vulnerability is real and unguarded:

1. `perasWeight` is a protocol parameter (`PerasParams.perasWeight`). A future era or testnet configuration with a large value (e.g., `Word64.maxBound / 2`) would make overflow reachable with just two certificates for the same block.
2. The same codebase already identified and guarded the identical pattern for `ByteSize32`, confirming developer awareness that `Sum Word64` requires explicit overflow protection in security-critical paths.
3. An adversary who can inject valid Peras certificates (received via the Peras mini-protocol) for many rounds all boosting the same block accumulates weight in `addToPerasWeightSnapshot` without any cap or overflow check.

The likelihood is **low** under current parameters but **structurally unmitigated** and escalates to **high** under any parameter regime with a larger `perasWeight`.

---

### Recommendation

1. Replace `deriving via Sum Word64 instance Semigroup PerasWeight` with a checked addition that saturates at `maxBound` or throws an error on overflow — analogous to the overflow guard in `pureTryAddTx` for `ByteSize32`.
2. Add an overflow guard in `weightBoostOfFragment` and `totalWeightOfFragment` (e.g., promote to `Natural` for intermediate accumulation, then check the result fits in `Word64` before converting back).
3. Add an overflow guard in `wsvTotalWeight` when adding `BlockNo` and `wsvWeightBoost`.
4. Add an overflow guard in `addToPerasWeightSnapshot` when combining weights for the same point.
5. Add a property-based test asserting that `totalWeightOfFragment` and `wsvTotalWeight` never produce a value smaller than either of their operands (which would indicate overflow).

---

### Proof of Concept

```haskell
-- Demonstrates that PerasWeight accumulation silently wraps.
-- Run in GHCi with the ouroboros-consensus library loaded.

import Ouroboros.Consensus.Peras.Params (PerasWeight(..))
import Data.Word (Word64)

half :: PerasWeight
half = PerasWeight (maxBound `div` 2 + 1)

-- Two boosts of (maxBound/2 + 1) each should exceed maxBound,
-- but instead wrap to 0 silently:
overflowed :: PerasWeight
overflowed = half <> half
-- overflowed == PerasWeight 0  (silent wrap)

-- In chain selection, a fragment with two such boosted blocks
-- would have wsvTotalWeight = BlockNo + 0 = BlockNo,
-- appearing no heavier than an unboosted chain of the same length.
-- preferCandidate would then reject it in favour of a shorter chain.
```

The same wrap occurs in `weightBoostOfFragment` (via `foldMap`) and `totalWeightOfFragment` (via `<>`), and in `addToPerasWeightSnapshot` (via `Map.insertWith (<>)`), all without any overflow detection or rejection. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L84-91)
```haskell
newtype PerasWeight
  = PerasWeight {unPerasWeight :: Word64}
  deriving Show via Quiet PerasWeight
  deriving stock Generic
  deriving newtype (Enum, Eq, Ord, NoThunks, Condense)

deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L131-132)
```haskell
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L259-267)
```haskell
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsMempool.hs (L390-421)
```haskell
-- This is modular arithmetic, so uses need to be concerned with overflow. For
-- example, see the related guard in
-- 'Ouroboros.Consensus.Mempool.Update.pureTryAddTx'. One important element is
-- anticipating the possibility of very large summands injected by the
-- adversary.
--
-- There is a temptation to use 'Natural' here, since it can never overflow.
-- However, some points in the interface do not easily handle 'Natural's, such
-- as encoders. Thus 'Natural' would merely defer the overflow concern, and
-- even risks instilling a false sense that overflow need not be considered at
-- all.
newtype ByteSize32 = ByteSize32 {unByteSize32 :: Word32}
  deriving stock Show
  deriving newtype (Eq, Ord)
  deriving newtype NFData
  deriving newtype Serialise
  deriving
    (Monoid, Semigroup)
    via (InstantiatedAt Measure (IgnoringOverflow ByteSize32))
  deriving
    NoThunks
    via OnlyCheckWhnfNamed "ByteSize" ByteSize32

-- | @'IgnoringOverflow' a@ has the same semantics as @a@, except it ignores
-- the fact that @a@ can overflow.
--
-- For example, @'Measure' 'Word32'@ is not lawful, because overflow violates
-- the /lattice-ordered monoid/ law. But @'Measure' (IgnoringOverflow
-- 'Word32')@ is lawful, since it explicitly ignores that case.
--
-- WARNING: anywhere this type occurs is a very strong indicator that overflow
-- will break assumptions, so overflow must therefore be guarded against.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Update.hs (L338-352)
```haskell
        Right txsz
          -- Check for overflow
          --
          -- No measure of a transaction can ever be negative, so the only way
          -- adding two measures could result in a smaller measure is if some
          -- modular arithmetic overflowed. Also, overflow necessarily yields a
          -- lesser result, since adding 'maxBound' is modularly equivalent to
          -- subtracting one. Recall that we're checking each individual addition.
          --
          -- We assume that the 'txMeasure' limit and the mempool capacity
          -- 'isCapacity' are much smaller than the modulus, and so this should
          -- never happen. Despite that, blocking until adding the transaction
          -- doesn't overflow seems like a reasonable way to handle this case.
          | not $ currentSize Measure.<= currentSize `Measure.plus` MkTxMeasureWithDiffTime txsz Measure.zero ->
              NotEnoughSpaceLeft
```
