### Title
Silent `Word64` Overflow in Era-Boundary Arithmetic Silently Corrupts Safe-Zone and Forecast Bounds - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Util.hs`)

---

### Summary

`addSlots`, `addEpochs`, and `addPerasRounds` in `Util.hs` perform plain `Word64` addition with no overflow detection. Their counterparts `countSlots`, `countEpochs`, and `countPerasRounds` guard against underflow only with `assert`, which GHC silently removes in optimised (production) builds. These primitives are the sole arithmetic layer used to compute era-boundary `Bound` records, safe-zone end slots, and cross-era forecast bounds. A silent overflow in any of them produces a structurally valid but numerically wrong `Bound`, corrupting every downstream slot↔epoch↔time translation and every `PastHorizonException` guard that depends on it.

---

### Finding Description

**Root cause — `Util.hs`**

```haskell
addSlots :: Word64 -> SlotNo -> SlotNo
addSlots n (SlotNo x) = SlotNo (x + n)          -- wraps silently on overflow

addEpochs :: Word64 -> EpochNo -> EpochNo
addEpochs n (EpochNo x) = EpochNo (x + n)       -- wraps silently on overflow

addPerasRounds :: Word64 -> PerasRoundNo -> PerasRoundNo
addPerasRounds n (PerasRoundNo x) = PerasRoundNo (x + n)  -- wraps silently

countSlots :: HasCallStack => SlotNo -> SlotNo -> Word64
countSlots (SlotNo to) (SlotNo fr) = assert (to >= fr) $ to - fr
-- assert is a no-op in -O builds; underflow wraps silently in production
``` [1](#0-0) 

**Propagation path 1 — `mkUpperBound` in `Summary.hs`**

```haskell
inEraSlots = inEraEpochs * unEpochSize eraEpochSize   -- Word64 × Word64, no overflow check
...
boundSlot = addSlots inEraSlots $ boundSlot lo         -- addSlots wraps silently
``` [2](#0-1) 

**Propagation path 2 — `applySafeZone` in `Infra.hs`**

```haskell
applySafeZone params@EraParams{..} start =
  case eraSafeZone of
    StandardSafeZone safeFromTip ->
      EraEnd
        . History.mkUpperBound params start
        . History.slotToEpochBound params start
        . History.addSlots safeFromTip   -- wraps if ledgerTip near maxBound
``` [3](#0-2) 

**Propagation path 3 — `crossEraForecastBound` in `Forecast.hs`**

```haskell
boundFromCurrentEra = addSlots currentLookahead tipSucc   -- wraps silently
boundFromNextEra    = addSlots nextLookahead transitionSlot  -- wraps silently
``` [4](#0-3) 

**Propagation path 4 — `ERelEpochToSlot` and `ERelPerasRoundNoToSlot` in `Qry.hs`**

```haskell
go (ERelEpochToSlot expr) = do
  e <- go expr
  return $ SlotInEra (getEpochInEra e * epochSize)   -- Word64 × Word64, no overflow check

go (ERelPerasRoundNoToSlot expr) = runPerasEnabledT $ do
  ...
  pure $ SlotInEra (relPerasRoundNo * perasRoundLength)  -- Word64 × Word64, no overflow check
``` [5](#0-4) 

**Cascade effect**

If `addSlots safeFromTip (SlotNo x)` overflows (producing a small slot number `s'`), the immediately following `countSlots s' (boundSlot lo)` receives `to < fr`. In production builds the `assert` is a no-op, so `to - fr` underflows to a huge `Word64`. That huge value is then divided by `epochSize` and fed into `addEpochs`, producing a wildly wrong epoch number for the era end `Bound`. Every subsequent `PastHorizonException` guard, slot↔epoch translation, and forecast-range check that reads this `Bound` will operate on incorrect data. [6](#0-5) 

---

### Impact Explanation

The `Summary` / `EraSummary` structure is the single source of truth for all hard-fork era boundary decisions in the consensus layer. A corrupted `Bound` (wrong `boundSlot`, `boundEpoch`, or `boundTime`) causes:

- **Incorrect `PastHorizonException` decisions**: a slot that is genuinely within the safe zone may be reported as past the horizon, causing valid headers to be rejected; conversely, a slot past the safe zone may be accepted, allowing headers from an unknown future era to pass validation.
- **Incorrect cross-era forecast bounds** (`crossEraForecastBound`): the node may accept ledger-view forecasts for slots that are actually outside the safe zone, or refuse to forecast for slots that are inside it, breaking the header/body split invariant.
- **Incorrect slot↔epoch↔time translations** used by the Shelley ledger's `EpochInfo` for reward calculations, stake-distribution snapshots, and protocol-parameter updates — all of which feed back into block and header validation.

These effects map to the "Hard-fork, era transition, ledger-view, query, or network-version mismatch that breaks cross-era consensus or ledger invariants" impact class.

---

### Likelihood Explanation

Triggering the overflow in `addSlots` requires a `SlotNo` value near `maxBound :: Word64 = 2^64 − 1`. Cardano mainnet has been running for roughly five years at ~1 slot/second, placing the current slot around 157 million — many orders of magnitude below the overflow threshold. The multiplication overflow in `inEraSlots = inEraEpochs * unEpochSize eraEpochSize` requires either an astronomically large era-transition epoch (governance-controlled) or an astronomically large epoch size (also governance-controlled). Neither is reachable by an unprivileged peer under normal operating conditions.

This is directly analogous to the external report's conclusion: the deviation from correct arithmetic behaviour exists in the code, the impact if triggered would be severe (incorrect consensus decisions), but there is presently no known way for an unprivileged peer to trigger it. Consistent with the external report's Medium downgrade, the likelihood is low.

---

### Recommendation

1. **Replace plain `Word64` addition with checked arithmetic** in `addSlots`, `addEpochs`, and `addPerasRounds`. Use `Data.Word`'s `addWordMaybe#` or a helper that calls `error`/throws an exception on overflow, mirroring the intent of the existing `assert` guards.
2. **Replace `assert` with unconditional runtime checks** in `countSlots`, `countEpochs`, and `countPerasRounds`. `assert` is silently removed by GHC in optimised builds; use an explicit `if`/`error` or `when (to < fr) $ error "..."` guard instead.
3. **Add an overflow check to the `inEraSlots` multiplication** in `mkUpperBound`:
   ```haskell
   inEraSlots = checkedMul inEraEpochs (unEpochSize eraEpochSize)
   ```
4. **Add the same check to `ERelEpochToSlot` and `ERelPerasRoundNoToSlot`** in `Qry.hs`.

---

### Proof of Concept

```
-- Minimal reproduction (private testnet or unit test):
-- Set eraEpochSize = EpochSize (maxBound `div` 2 + 1)
-- Set hiEpoch such that inEraEpochs = 2
-- Then: inEraSlots = 2 * (maxBound `div` 2 + 1) = maxBound + 2 → wraps to 1
-- addSlots 1 (boundSlot lo) produces boundSlot lo + 1 instead of the correct
-- boundSlot lo + maxBound + 2, silently corrupting the era end Bound.
-- All subsequent PastHorizonException guards and slot translations use the wrong bound.
```

The `assert`-disabled underflow can be demonstrated by compiling with `-O` and calling `countSlots (SlotNo 0) (SlotNo 1)` — in a debug build this throws `AssertionFailed`; in a production build it silently returns `maxBound :: Word64`. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Util.hs (L22-48)
```haskell
addSlots :: Word64 -> SlotNo -> SlotNo
addSlots n (SlotNo x) = SlotNo (x + n)

subSlots :: Word64 -> SlotNo -> SlotNo
subSlots n (SlotNo x) = assert (x >= n) $ SlotNo (x - n)

addEpochs :: Word64 -> EpochNo -> EpochNo
addEpochs n (EpochNo x) = EpochNo (x + n)

addPerasRounds :: Word64 -> PerasRoundNo -> PerasRoundNo
addPerasRounds n (PerasRoundNo x) = PerasRoundNo (x + n)

-- | @countSlots to fr@ counts the slots from @fr@ to @to@ (@to >= fr@)
countSlots :: HasCallStack => SlotNo -> SlotNo -> Word64
countSlots (SlotNo to) (SlotNo fr) = assert (to >= fr) $ to - fr
 where
  _ = keepRedundantConstraint (Proxy :: Proxy HasCallStack)

-- | @countEpochs to fr@ counts the epochs from @fr@ to @to@ (@to >= fr@)
countEpochs :: HasCallStack => EpochNo -> EpochNo -> Word64
countEpochs (EpochNo to) (EpochNo fr) = assert (to >= fr) $ to - fr
 where
  _ = keepRedundantConstraint (Proxy :: Proxy HasCallStack)

countPerasRounds :: HasCallStack => PerasRoundNo -> PerasRoundNo -> Word64
countPerasRounds (PerasRoundNo to) (PerasRoundNo fr) = assert (to >= fr) $ to - fr
 where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L125-141)
```haskell
mkUpperBound EraParams{..} lo hiEpoch =
  Bound
    { boundTime = addRelTime inEraTime $ boundTime lo
    , boundSlot = addSlots inEraSlots $ boundSlot lo
    , boundEpoch = hiEpoch
    , boundPerasRound = addPerasRounds <$> inEraPerasRounds <*> boundPerasRound lo
    }
 where
  inEraEpochs, inEraSlots :: Word64
  inEraEpochs = countEpochs hiEpoch (boundEpoch lo)
  inEraSlots = inEraEpochs * unEpochSize eraEpochSize

  inEraPerasRounds :: PerasEnabled Word64
  inEraPerasRounds = div <$> PerasEnabled inEraSlots <*> (unPerasRoundLength <$> eraPerasRoundLength)

  inEraTime :: NominalDiffTime
  inEraTime = fromIntegral inEraSlots * getSlotLength eraSlotLength
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L148-155)
```haskell
slotToEpochBound :: EraParams -> Bound -> SlotNo -> EpochNo
slotToEpochBound EraParams{eraEpochSize = EpochSize epochSize} lo hiSlot =
  addEpochs
    (if inEpoch == 0 then epochs else epochs + 1)
    (boundEpoch lo)
 where
  slots = countSlots hiSlot (boundSlot lo)
  (epochs, inEpoch) = slots `divMod` epochSize
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State/Infra.hs (L291-301)
```haskell
  applySafeZone :: EraParams -> Bound -> SlotNo -> EraEnd
  applySafeZone params@EraParams{..} start =
    case eraSafeZone of
      UnsafeIndefiniteSafeZone ->
        const EraUnbounded
      StandardSafeZone safeFromTip ->
        EraEnd
          . History.mkUpperBound params start
          . History.slotToEpochBound params start
          . History.addSlots safeFromTip

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Forecast.hs (L196-200)
```haskell
    return $ addSlots currentLookahead tipSucc

  -- Upper bound arising from blocks in the next era
  boundFromNextEra :: SlotNo
  boundFromNextEra = addSlots nextLookahead transitionSlot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L358-364)
```haskell
  go (ERelEpochToSlot expr) = do
    e <- go expr
    return $ SlotInEra (getEpochInEra e * epochSize)
  go (ERelPerasRoundNoToSlot expr) = runPerasEnabledT $ do
    PerasRoundNoInEra relPerasRoundNo <- PerasEnabledT $ go expr
    PerasRoundLength perasRoundLength <- PerasEnabledT . Just $ eraPerasRoundLength
    pure $ SlotInEra (relPerasRoundNo * perasRoundLength)
```
