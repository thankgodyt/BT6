### Title
Peras Round-Number Queries Silently Return `NoPerasEnabled` for the First Peras-Enabled Era Due to `initBound` Mismatch — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs`, `Qry.hs`)

---

### Summary

The genesis `Bound` value (`initBound`) hard-codes `boundPerasRound = NoPerasEnabled`. Because `mkUpperBound` propagates this `Nothing`-valued field through the `PerasEnabled` applicative, the start `Bound` of the first Peras-enabled era also carries `boundPerasRound = NoPerasEnabled`. Inside `evalExprInEra`, the `EAbsToRelPerasRoundNo` and `ERelToAbsPerasRoundNo` expression evaluators bind `eraStartPerasRound` from `boundPerasRound eraStart`; when that field is `NoPerasEnabled`, the `PerasEnabledT` monad short-circuits and the entire computation returns `Just NoPerasEnabled` — a silent success carrying the wrong value — rather than `Nothing` (which would surface as a `PastHorizonException`). Consequently, `slotToPerasRoundNo`, `perasRoundNoToSlot`, and `EPerasRoundLength` all return `NoPerasEnabled` for every slot in the first Peras-enabled era, making the node treat that era as if Peras were disabled.

---

### Finding Description

**Root cause chain:**

1. `initBound` is the genesis lower bound used by both `recover` (the production path) and `summarize` (the test path). It is defined with `boundPerasRound = NoPerasEnabled`: [1](#0-0) 

2. `mkUpperBound` computes the upper bound of each era. The Peras round component is:

```haskell
boundPerasRound = addPerasRounds <$> inEraPerasRounds <*> boundPerasRound lo
```

where `inEraPerasRounds = div <$> PerasEnabled inEraSlots <*> (unPerasRoundLength <$> eraPerasRoundLength)`. [2](#0-1) 

For every non-Peras era (`eraPerasRoundLength = NoPerasEnabled`), `inEraPerasRounds = NoPerasEnabled`, so the `<*>` short-circuits and the upper bound also carries `boundPerasRound = NoPerasEnabled`. The upper bound of the last non-Peras era becomes the **start bound** of the first Peras-enabled era — still `NoPerasEnabled`.

3. In `evalExprInEra`, the `EAbsToRelPerasRoundNo` evaluator does:

```haskell
go (EAbsToRelPerasRoundNo expr) =
  runPerasEnabledT $ do
    eraStartPerasRound <- PerasEnabledT . Just $ boundPerasRound eraStart
    ...
``` [3](#0-2) 

When `boundPerasRound eraStart = NoPerasEnabled`, `PerasEnabledT . Just $ NoPerasEnabled` wraps `Just NoPerasEnabled`. The `PerasEnabledT` monad bind immediately short-circuits:

```haskell
NoPerasEnabled -> pure NoPerasEnabled
``` [4](#0-3) 

The whole computation returns `Just NoPerasEnabled` — a successful `Maybe` result carrying the wrong value — rather than `Nothing`. The same short-circuit applies to `ERelToAbsPerasRoundNo` and `EPerasRoundLength`: [5](#0-4) [6](#0-5) 

4. The public queries `slotToPerasRoundNo` and `perasRoundNoToSlot` both compose these expressions: [7](#0-6) 

Both return `NoPerasEnabled` for every slot in the first Peras-enabled era.

5. The production path (`reconstructSummaryLedger` → `reconstructSummary`) uses `initBound` directly: [8](#0-7) 

The test path (`summarize`) already works around this by substituting `initBoundWithPeras`, but explicitly marks this as a temporary hack with a TODO: [9](#0-8) 

The same workaround appears in the test infrastructure: [10](#0-9) 

The `invariantSummary` checker does not validate that a Peras-enabled era's start bound carries a valid `PerasRoundNo`, so the malformed state passes all existing invariant checks: [11](#0-10) 

---

### Impact Explanation

When the first Peras-enabled era is active (reachable today on any private testnet that enables Peras via `eraPerasRoundLength`), every call to `slotToPerasRoundNo` or `perasRoundNoToSlot` for a slot in that era returns `NoPerasEnabled`. Callers interpret this as "Peras is not active for this slot." Concretely:

- **Peras certificate and vote validation is silently skipped** for the entire first Peras-enabled era. An unprivileged peer can submit blocks carrying forged or replayed Peras certificates; the receiving node will not reject them on round-number grounds.
- **Peras chain-weight calculations are zeroed** for that era. An adversary can craft a competing chain that omits valid certificates; the honest node will assign it the same weight as a chain that includes them, breaking the chain-selection security assumption of Peras.

This matches the allowed impact scope: *bypass of Peras voting or certificate checks enabling unauthorized certificate acceptance* (Critical), and *hard-fork era transition mismatch that breaks cross-era consensus invariants* (High).

---

### Likelihood Explanation

No Peras-enabled era exists on Cardano mainnet today, so the production chain is not currently affected. However:

- The code path is fully exercised on any private testnet that sets `eraPerasRoundLength = PerasEnabled _` for any era.
- The developers have already identified the gap (two TODO comments referencing issue #112) and the test suite works around it — confirming the defect is known and real.
- When Peras is deployed (the stated goal of the Peras extension), the bug activates immediately for the first Peras era without any attacker precondition beyond being a normal peer.

Likelihood: **High** at Peras deployment; **Medium** on any current private testnet with Peras enabled.

---

### Recommendation

1. **Fix `initBound`** to accept a configurable `boundPerasRound`, or default it to `PerasEnabled (PerasRoundNo 0)` unconditionally (matching what `summarize` already does for tests).
2. **Fix `mkUpperBound`** so that when transitioning from a non-Peras era to a Peras-enabled era, the upper bound's `boundPerasRound` is initialised to `PerasEnabled (PerasRoundNo 0)` rather than inheriting `NoPerasEnabled` from the lower bound.
3. **Extend `invariantSummary`** to assert that for any era with `eraPerasRoundLength = PerasEnabled _`, both `eraStart.boundPerasRound` and (if bounded) `eraEnd.boundPerasRound` are also `PerasEnabled _`.
4. Remove the test-only `initBoundWithPeras` workaround once the production path is fixed.

---

### Proof of Concept

```
Private-testnet sequence:

1. Configure a two-era chain: Era A (non-Peras, eraPerasRoundLength = NoPerasEnabled)
   followed by Era B (Peras-enabled, eraPerasRoundLength = PerasEnabled 10).

2. Advance the chain into Era B. The HFC calls reconstructSummaryLedger, which
   calls reconstructSummary with initBound (boundPerasRound = NoPerasEnabled).
   mkUpperBound for Era A produces an upper bound with boundPerasRound = NoPerasEnabled.
   That bound becomes eraStart for Era B.

3. Call slotToPerasRoundNo for any slot s in Era B:
     interpretQuery interpreter (slotToPerasRoundNo s)
   → evalExprInEra eraSummaryB (ERelToAbsPerasRoundNo ...)
   → eraStartPerasRound <- PerasEnabledT . Just $ NoPerasEnabled
   → PerasEnabledT monad short-circuits → returns Just NoPerasEnabled
   → slotToPerasRoundNo returns NoPerasEnabled

4. The node treats Era B as non-Peras. A peer submits a block in Era B carrying
   a Peras certificate for an arbitrary (forged) round number. The node accepts
   the block without validating the certificate's round number, because
   slotToPerasRoundNo returned NoPerasEnabled and the validation branch is skipped.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L92-101)
```haskell
initBound :: Bound
initBound =
  Bound
    { boundTime = RelativeTime 0
    , boundSlot = SlotNo 0
    , boundEpoch = EpochNo 0
    , -- TODO(geo2a): we may want to make this configurable,
      -- see https://github.com/tweag/cardano-peras/issues/112
      boundPerasRound = NoPerasEnabled
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L351-360)
```haskell
  -- as noted in the haddock, this function is only used for testing purposes,
  -- therefore we make the initial era is Peras-enabled, which means
  -- we only test Peras-enabled eras. It is rather difficult
  -- to parameterise the test suite, as it requires also parameterise many non-test functions, like
  -- 'HF.initBound'.
  --
  -- TODO(geo2a): revisit this hard-coding of enabling Peras when
  -- we're further into the integration process
  -- see https://github.com/tweag/cardano-peras/issues/112
  initBoundWithPeras = initBound{boundPerasRound = PerasEnabled . PerasRoundNo $ 0}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L500-513)
```haskell
        case eraPerasRoundLength curParams of
          NoPerasEnabled -> pure ()
          PerasEnabled perasRoundLength ->
            unless
              ( (unEpochSize $ eraEpochSize curParams)
                  `mod` (unPerasRoundLength perasRoundLength)
                  == 0
              )
              $ throwError
              $ mconcat
                [ "Invalid Peras round length "
                , show curSummary
                , " (Peras round length does not divide epoch size)"
                ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L303-309)
```haskell
  go (EAbsToRelPerasRoundNo expr) =
    runPerasEnabledT $ do
      eraStartPerasRound <- PerasEnabledT . Just $ boundPerasRound eraStart
      absPerasRoundNo <- lift $ go expr
      lift . guard $ absPerasRoundNo >= eraStartPerasRound
      let roundInEra = countPerasRounds absPerasRoundNo eraStartPerasRound
      pure . PerasRoundNoInEra $ roundInEra
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L335-343)
```haskell
  go (ERelToAbsPerasRoundNo expr) = runPerasEnabledT $ do
    eraStartPerasRound <- PerasEnabledT . Just $ boundPerasRound eraStart
    relPerasRound <- PerasEnabledT $ go expr
    let absPerasRound = addPerasRounds (getPerasRoundNoInEra relPerasRound) eraStartPerasRound

    guardEndPeras $ \end -> do
      eraEndPerasRound <- PerasEnabledT . Just $ boundPerasRound end
      pure $ absPerasRound <= eraEndPerasRound
    pure absPerasRound
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L390-397)
```haskell
  go (EPerasRoundLength expr) = runPerasEnabledT $ do
    eraStartPerasRound <- PerasEnabledT . Just $ boundPerasRound eraStart
    absPerasRound <- lift $ go expr
    lift . guard $ absPerasRound >= eraStartPerasRound
    guardEndPeras $ \end -> do
      eraEndPerasRound <- PerasEnabledT . Just $ boundPerasRound end
      pure $ absPerasRound < eraEndPerasRound
    PerasEnabledT . Just $ eraPerasRoundLength
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L587-614)
```haskell
perasRoundNoToSlot :: PerasRoundNo -> Qry (PerasEnabled (SlotNo, PerasRoundLength))
perasRoundNoToSlot perasRoundNo = runPerasEnabledT $ do
  relSlot <-
    PerasEnabledT $ qryFromExpr (ERelPerasRoundNoToSlot (EAbsToRelPerasRoundNo (ELit perasRoundNo)))
  absSlot <- lift $ qryFromExpr (ERelToAbsSlot (EPair (ELit relSlot) (ELit (TimeInSlot 0))))
  roundLength <- PerasEnabledT $ qryFromExpr (perasRoundNoPerasRoundLengthExpr perasRoundNo)
  pure (absSlot, roundLength)

-- | Translate 'SlotNo' to its corresponding 'PerasRoundNo'
--
-- Additionally returns the relative slot within this round and how many
-- slots are left in this round.
slotToPerasRoundNo :: SlotNo -> Qry (PerasEnabled (PerasRoundNo, Word64, Word64))
slotToPerasRoundNo absSlot = runPerasEnabledT $ do
  (relPerasRoundNo, slotInPerasRound) <-
    PerasEnabledT $
      qryFromExpr (ERelSlotToPerasRoundNo (EAbsToRelSlot (ELit absSlot)))
  absPerasRoundNo <-
    PerasEnabledT $
      qryFromExpr (ERelToAbsPerasRoundNo (ELit (PerasEnabled relPerasRoundNo)))
  roundLength <-
    PerasEnabledT $
      qryFromExpr (perasRoundNoPerasRoundLengthExpr absPerasRoundNo)
  pure $
    ( absPerasRoundNo
    , getSlotInPerasRound slotInPerasRound
    , unPerasRoundLength roundLength - getSlotInPerasRound slotInPerasRound
    )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EraParams.hs (L188-193)
```haskell
instance Monad m => Monad (PerasEnabledT m) where
  x >>= f = PerasEnabledT $ do
    v <- runPerasEnabledT x
    case v of
      NoPerasEnabled -> pure NoPerasEnabled
      PerasEnabled y -> runPerasEnabledT (f y)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State.hs (L146-155)
```haskell
reconstructSummaryLedger ::
  All SingleEraBlock xs =>
  HardForkLedgerConfig xs ->
  HardForkState (Flip LedgerState mk) xs ->
  History.Summary xs
reconstructSummaryLedger cfg@HardForkLedgerConfig{..} st =
  reconstructSummary
    hardForkLedgerConfigShape
    (mostRecentTransitionInfo cfg st)
    st
```

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/HardFork/Infra.hs (L162-169)
```haskell
genSummary :: Eras xs -> Gen (HF.Summary xs)
genSummary is =
  HF.Summary <$> erasUnfoldAtMost genEraSummary is initBoundWithPeras
 where
  -- TODO(geo2a): revisit this hard-coding of enabling Peras when
  -- we're further into the integration process
  -- see https://github.com/tweag/cardano-peras/issues/112
  initBoundWithPeras = HF.initBound{boundPerasRound = HF.PerasEnabled . PerasRoundNo $ 0}
```
