### Title
`initBound` Missing Peras Round Offset Causes All Cross-Era Peras Round Queries to Return `NoPerasEnabled` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs`)

---

### Summary

`initBound` — the genesis `Bound` used as the starting point for all era-summary construction in the production code path — sets `boundPerasRound = NoPerasEnabled`. Because `mkUpperBound` computes the upper-bound's `boundPerasRound` via the `Applicative` instance of `PerasEnabled` (which is `Maybe`-like), and because `Nothing <*> _ = Nothing`, every era bound derived from `initBound` also carries `NoPerasEnabled`. This means that in the production code path (`reconstructSummaryLedger` → `reconstructSummary` → `mkUpperBound`), the `boundPerasRound` field of every `Bound` is permanently `NoPerasEnabled`, regardless of whether the era has `eraPerasRoundLength = PerasEnabled someLength`. As a result, the HFC query expressions `EAbsToRelPerasRoundNo` and `ERelToAbsPerasRoundNo` — and therefore the public queries `perasRoundNoToSlot` and `slotToPerasRoundNo` — always return `NoPerasEnabled`, silently treating every era as Peras-disabled even when Peras is configured and active.

---

### Finding Description

**Root cause — `initBound` omits the Peras round offset:** [1](#0-0) 

`initBound` is the genesis `Bound` used by `recover` (the production deserialization path) and by `reconstructSummary` as the starting lower bound for the first era: [2](#0-1) 

**Propagation through `mkUpperBound`:**

`mkUpperBound` computes the upper bound's `boundPerasRound` as:

```haskell
boundPerasRound = addPerasRounds <$> inEraPerasRounds <*> boundPerasRound lo
``` [3](#0-2) 

`PerasEnabled` is a `newtype` over `Maybe` and derives its `Applicative` instance from `Maybe`: [4](#0-3) 

Because `Just f <*> Nothing = Nothing`, whenever `boundPerasRound lo = NoPerasEnabled`, the result is `NoPerasEnabled` regardless of `inEraPerasRounds`. Since `lo` for the first era is always `initBound` (with `NoPerasEnabled`), and each subsequent era's lower bound is the upper bound of the previous era (also `NoPerasEnabled`), **every `Bound` in the production summary has `boundPerasRound = NoPerasEnabled`**.

**Consequence in the query engine:**

The `EAbsToRelPerasRoundNo` expression reads `boundPerasRound eraStart` to establish the era's starting round: [5](#0-4) 

`PerasEnabledT . Just $ NoPerasEnabled` creates `PerasEnabledT (Just NoPerasEnabled)`. The `>>=` for `PerasEnabledT` short-circuits on `NoPerasEnabled`:

```haskell
case v of
  NoPerasEnabled -> pure NoPerasEnabled   -- always taken
  PerasEnabled y -> runPerasEnabledT (f y)
```

So the entire expression returns `Just NoPerasEnabled`, and the query reports Peras as disabled. The same applies to `ERelToAbsPerasRoundNo`: [6](#0-5) 

**Downstream breakage:**

`perasRoundNoToSlot` and `slotToPerasRoundNo` always return `NoPerasEnabled`: [7](#0-6) 

`perasRoundStart` in `Voting/View.hs` therefore always throws `PerasQryExceptionPerasDisabled`: [8](#0-7) 

**Contrast with the test-only path:**

The `summarize` function (explicitly marked as a reference/test implementation) works around this by using a local `initBoundWithPeras`: [9](#0-8) 

The production path (`reconstructSummaryLedger`) never calls `summarize` and never applies this workaround: [10](#0-9) 

---

### Impact Explanation

When Peras is enabled, every Peras round-number query against the production HFC summary silently returns `NoPerasEnabled`. This breaks:

1. **Certificate inclusion validation** — `perasRoundStart` cannot determine round boundaries, so certificate arrival-slot and round-membership checks always fail with `PerasQryExceptionPerasDisabled`.
2. **Chain selection** — Peras weight boosts depend on correctly identifying which round a certificate belongs to. With round queries broken, the weight-boost accounting is incorrect, causing chain selection to diverge from the intended Peras semantics.
3. **Cross-era Peras invariants** — The `Bound.boundPerasRound` field is the authoritative cross-era anchor for Peras round numbering. Its permanent `NoPerasEnabled` value breaks the invariant that era bounds correctly encode the cumulative Peras round count, which is a cross-era consensus ledger invariant.

This matches the allowed impact: **High — hard-fork/era-transition/query mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes.**

---

### Likelihood Explanation

The bug is in the production code path (`recover` → `initBound` → `mkUpperBound` → `reconstructSummary`). It is triggered unconditionally whenever Peras is enabled on any network (private testnet or mainnet). No attacker action is required; the miscalculation occurs automatically during normal node operation. The only reason it is not currently observable on mainnet is that Peras is disabled by default. Any operator enabling Peras will immediately encounter the broken round queries.

---

### Recommendation

Initialize `initBound` with `boundPerasRound = PerasEnabled (PerasRoundNo 0)` when Peras is active, mirroring the workaround already applied in `summarize`:

```haskell
initBound :: Bound
initBound =
  Bound
    { boundTime      = RelativeTime 0
    , boundSlot      = SlotNo 0
    , boundEpoch     = EpochNo 0
    , boundPerasRound = PerasEnabled (PerasRoundNo 0)  -- was: NoPerasEnabled
    }
```

Alternatively, make `initBound` configurable (as the existing TODO at line 98–100 suggests) so that Peras-enabled deployments can supply the correct starting round. The `recover` function and any other site that seeds the `HardForkState` with `initBound` must be updated consistently. [1](#0-0) 

---

### Proof of Concept

Trace through the production path for a two-era chain where era 1 is Peras-enabled with `PerasRoundLength 10` and `EpochSize 100`:

1. **Era 1 lower bound** = `initBound` → `boundPerasRound = NoPerasEnabled`
2. **`mkUpperBound` for era 1→2**:
   - `inEraPerasRounds = div <$> PerasEnabled 100 <*> PerasEnabled 10 = PerasEnabled 10`
   - `boundPerasRound = addPerasRounds <$> PerasEnabled 10 <*> NoPerasEnabled`
   - `= Just (addPerasRounds 10) <*> Nothing = Nothing = NoPerasEnabled`
3. **Era 2 lower bound** = `NoPerasEnabled`
4. **`perasRoundNoToSlot (PerasRoundNo 5)`** evaluates `EAbsToRelPerasRoundNo`:
   - `eraStartPerasRound <- PerasEnabledT (Just NoPerasEnabled)` → short-circuits to `Just NoPerasEnabled`
   - Query returns `NoPerasEnabled`
5. **`perasRoundStart (PerasRoundNo 5)`** receives `Right NoPerasEnabled` → throws `PerasQryExceptionPerasDisabled`

Certificate inclusion and chain-selection weight calculations that call `perasRoundStart` will all throw this exception, effectively disabling Peras despite it being configured as active.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L348-360)
```haskell
summarize ledgerTip = \(Shape shape) (Transitions transitions) ->
  Summary $ go initBoundWithPeras shape transitions
 where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State.hs (L93-113)
```haskell
recover ::
  forall f xs.
  CanHardFork xs =>
  Telescope (K Past) f xs -> HardForkState f xs
recover =
  case isNonEmpty (Proxy @xs) of
    ProofNonEmpty{} ->
      HardForkState
        . Telescope.bihmap
          (\(Pair _ past) -> past)
          recoverCurrent
        . Telescope.scanl
          (InPairs.hpure $ ScanNext $ const $ K . pastEnd . unK)
          (K History.initBound)
 where
  recoverCurrent :: Product (K History.Bound) f blk -> Current f blk
  recoverCurrent (Pair (K prevEnd) st) =
    Current
      { currentStart = prevEnd
      , currentState = st
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EraParams.hs (L155-168)
```haskell
newtype PerasEnabled a = MkPerasEnabled (Maybe a)
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
  deriving newtype (Functor, Applicative, Monad)

pattern PerasEnabled :: a -> PerasEnabled a
pattern PerasEnabled x <- MkPerasEnabled (Just !x)
 where
  PerasEnabled !x = MkPerasEnabled (Just x)

pattern NoPerasEnabled :: PerasEnabled a
pattern NoPerasEnabled = MkPerasEnabled Nothing

{-# COMPLETE PerasEnabled, NoPerasEnabled #-}
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L584-614)
```haskell
-- | Translate 'PerasRoundNo' to the 'SlotNo' of the first slot in that Peras round
--
-- Additionally returns the length of the round.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L108-120)
```haskell
-- | Slot number at the start of a Peras round
perasRoundStart ::
  PerasRoundNo ->
  PerasQry xs SlotNo
perasRoundStart roundNo = PerasQry $ do
  summary <- ask
  case HF.runQuery (HF.perasRoundNoToSlot roundNo) summary of
    Left pastHorizon ->
      throwError (PerasQryExceptionPastHorizon pastHorizon)
    Right NoPerasEnabled ->
      throwError PerasQryExceptionPerasDisabled
    Right (PerasEnabled (slotNo, _)) ->
      return slotNo
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger.hs (L318-324)
```haskell
instance All SingleEraBlock xs => HasHardForkHistory (HardForkBlock xs) where
  type HardForkIndices (HardForkBlock xs) = xs

  hardForkSummary cfg =
    State.reconstructSummaryLedger cfg
      . hardForkLedgerStatePerEra

```
