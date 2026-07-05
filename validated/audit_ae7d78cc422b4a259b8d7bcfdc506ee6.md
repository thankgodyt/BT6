### Title
Incomplete Peras-enabled guard in `evalExprInEra` silently disables Peras round queries when era start `Bound` has `NoPerasEnabled` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs`)

---

### Summary

In `evalExprInEra`, the `EAbsToRelPerasRoundNo`, `ERelToAbsPerasRoundNo`, and `EPerasRoundLength` expression cases check only `boundPerasRound eraStart` (the `PerasEnabled PerasRoundNo` field of the era's start `Bound`) to decide whether Peras is active. They do **not** also check `eraPerasRoundLength` (the `PerasEnabled PerasRoundLength` field of `EraParams`). Because `initBound` initialises `boundPerasRound = NoPerasEnabled` and `mkUpperBound` propagates `NoPerasEnabled` through every non-Peras era, the start `Bound` of the **first** Peras-enabled era will always carry `NoPerasEnabled`. The three affected cases therefore short-circuit to `Just NoPerasEnabled` — silently reporting "Peras disabled" — even though `eraPerasRoundLength = PerasEnabled x` for that era. Every downstream consumer that calls `perasRoundNoToSlot` (e.g. `perasRoundStart`, `perasChainAtCandidateBlock`) then throws `PerasQryExceptionPerasDisabled` and falls back to weight-free chain selection, defeating the Peras security assumption.

---

### Finding Description

**Root cause — `evalExprInEra`, `EAbsToRelPerasRoundNo` case:**

```haskell
go (EAbsToRelPerasRoundNo expr) =
  runPerasEnabledT $ do
    eraStartPerasRound <- PerasEnabledT . Just $ boundPerasRound eraStart
    -- ^^^ checks ONLY boundPerasRound eraStart, never eraPerasRoundLength
    absPerasRoundNo <- lift $ go expr
    lift . guard $ absPerasRoundNo >= eraStartPerasRound
    let roundInEra = countPerasRounds absPerasRoundNo eraStartPerasRound
    pure . PerasRoundNoInEra $ roundInEra
``` [1](#0-0) 

The same pattern appears in `ERelToAbsPerasRoundNo` and `EPerasRoundLength`: [2](#0-1) [3](#0-2) 

When `boundPerasRound eraStart = NoPerasEnabled`, the `PerasEnabledT Maybe` monad short-circuits: `PerasEnabledT (Just NoPerasEnabled)` binds to `pure NoPerasEnabled`, so the entire computation returns `Just NoPerasEnabled` — "Peras disabled" — regardless of `eraPerasRoundLength`.

**Why `boundPerasRound eraStart` is always `NoPerasEnabled` for the first Peras era:**

`initBound` (the genesis bound used by `initHardForkState`) sets `boundPerasRound = NoPerasEnabled`: [4](#0-3) 

`initHardForkState` uses `History.initBound` directly: [5](#0-4) 

`mkUpperBound` propagates `NoPerasEnabled` from the lower bound whenever `eraPerasRoundLength = NoPerasEnabled`:

```haskell
boundPerasRound = addPerasRounds <$> inEraPerasRounds <*> boundPerasRound lo
-- inEraPerasRounds = div <$> PerasEnabled inEraSlots <*> (unPerasRoundLength <$> eraPerasRoundLength)
-- If eraPerasRoundLength = NoPerasEnabled → inEraPerasRounds = NoPerasEnabled
-- NoPerasEnabled <*> anything = NoPerasEnabled
``` [6](#0-5) 

Every pre-Peras era (Byron through Dijkstra today) has `eraPerasRoundLength = NoPerasEnabled`: [7](#0-6) 

So the chain of era bounds is: `initBound (NoPerasEnabled)` → era-1 upper bound `(NoPerasEnabled)` → … → first Peras era start `(NoPerasEnabled)`. The first Peras era therefore always has `boundPerasRound eraStart = NoPerasEnabled`, triggering the bug.

**Contrast with the correctly-implemented sibling cases:**

`ERelSlotToPerasRoundNo` and `ERelPerasRoundNoToSlot` check `eraPerasRoundLength` directly and are unaffected: [8](#0-7) 

**Test code explicitly papers over the bug** by substituting `initBoundWithPeras` (which forces `PerasEnabled (PerasRoundNo 0)`) for `initBound`, confirming the production path is unprotected: [9](#0-8) 

**Downstream impact path:**

`perasRoundStart` calls `perasRoundNoToSlot` (which uses `EAbsToRelPerasRoundNo`). When the query returns `NoPerasEnabled`, it throws `PerasQryExceptionPerasDisabled`: [10](#0-9) 

`perasChainAtCandidateBlock` calls `perasRoundStart`, so it also fails: [11](#0-10) 

---

### Impact Explanation

When Peras is configured as enabled (i.e., `eraPerasRoundLength = PerasEnabled x` for some era), every call to `perasRoundNoToSlot` or `perasRoundStart` in that era returns `PerasQryExceptionPerasDisabled`. Chain selection falls back to weight-free (length-only) Praos selection. An unprivileged peer can present a longer chain that carries no Peras certificates; the honest node will prefer it over a shorter chain that carries valid Peras certificates, violating the Peras security assumption that certificate-weighted chains are preferred. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a less-secure chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

**Medium.** All current Cardano eras set `eraPerasRoundLength = NoPerasEnabled`, so the bug is latent today. It becomes reachable the moment any era is configured with `eraPerasRoundLength = PerasEnabled x` — which is the explicit goal of the ongoing Peras integration (tracked by `https://github.com/tweag/cardano-peras/issues/112`). The test suite already works around the bug with `initBoundWithPeras`, meaning the defect will not be caught by existing tests when Peras is enabled in production configuration.

---

### Recommendation

In `evalExprInEra`, the `EAbsToRelPerasRoundNo`, `ERelToAbsPerasRoundNo`, and `EPerasRoundLength` cases must check **both** `boundPerasRound eraStart` **and** `eraPerasRoundLength`. Specifically:

- If `eraPerasRoundLength = NoPerasEnabled`, return `NoPerasEnabled` (Peras not active in this era).
- If `eraPerasRoundLength = PerasEnabled _` but `boundPerasRound eraStart = NoPerasEnabled`, treat the era start as `PerasRoundNo 0` (or derive it from the era's slot/epoch start) rather than short-circuiting to `NoPerasEnabled`.

Additionally, `mkUpperBound` should propagate a valid `PerasRoundNo` into the upper bound when `eraPerasRoundLength = PerasEnabled _`, even if the lower bound has `NoPerasEnabled`, so that subsequent eras inherit a correct start round. The `initBound` genesis bound should also be made configurable (as the TODO at line 98–100 of `Summary.hs` already notes) so that the first Peras era can be given a meaningful `boundPerasRound`.

---

### Proof of Concept

1. Configure a two-era chain: era A with `eraPerasRoundLength = NoPerasEnabled`, era B with `eraPerasRoundLength = PerasEnabled 10`.
2. Advance the chain into era B. The `HardForkState` for era B has `currentStart = mkUpperBound paramsA initBound epochTransition`, where `boundPerasRound = NoPerasEnabled` (because `paramsA.eraPerasRoundLength = NoPerasEnabled`).
3. Call `HF.runQuery (HF.perasRoundNoToSlot (PerasRoundNo 5)) summary`.
4. `evalExprInEra` for era B evaluates `EAbsToRelPerasRoundNo`: `PerasEnabledT . Just $ boundPerasRound eraStart` = `PerasEnabledT (Just NoPerasEnabled)`. The `PerasEnabledT Maybe` monad short-circuits; result = `Just NoPerasEnabled`.
5. `perasRoundStart` receives `Right NoPerasEnabled` and throws `PerasQryExceptionPerasDisabled`.
6. `perasChainAtCandidateBlock` propagates the exception; Peras chain selection is skipped entirely.
7. A peer presenting a chain of length `L+1` with zero Peras certificates is preferred over the honest chain of length `L` with valid certificates — violating the Peras security invariant.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L361-368)
```haskell
  go (ERelPerasRoundNoToSlot expr) = runPerasEnabledT $ do
    PerasRoundNoInEra relPerasRoundNo <- PerasEnabledT $ go expr
    PerasRoundLength perasRoundLength <- PerasEnabledT . Just $ eraPerasRoundLength
    pure $ SlotInEra (relPerasRoundNo * perasRoundLength)
  go (ERelSlotToPerasRoundNo expr) = runPerasEnabledT $ do
    SlotInEra relSlot <- lift $ go expr
    PerasRoundLength perasRoundLength <- PerasEnabledT . Just $ eraPerasRoundLength
    pure . bimap PerasRoundNoInEra SlotInPerasRound $ relSlot `divMod` perasRoundLength
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L125-131)
```haskell
mkUpperBound EraParams{..} lo hiEpoch =
  Bound
    { boundTime = addRelTime inEraTime $ boundTime lo
    , boundSlot = addSlots inEraSlots $ boundSlot lo
    , boundEpoch = hiEpoch
    , boundPerasRound = addPerasRounds <$> inEraPerasRounds <*> boundPerasRound lo
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L349-360)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State/Infra.hs (L60-67)
```haskell
initHardForkState :: f x -> HardForkState f (x ': xs)
initHardForkState st =
  HardForkState $
    TZ $
      Current
        { currentStart = History.initBound
        , currentState = st
        }
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L178-180)
```haskell
    , -- TODO(geo2a): enabled Peras conditionally in the Dijkstra era
      -- see https://github.com/tweag/cardano-peras/issues/112
      eraPerasRoundLength = HardFork.NoPerasEnabled
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L109-120)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L137-148)
```haskell
perasChainAtCandidateBlock blockMinSlots currRoundNo currChain = do
  -- Slot number at the start of the current round
  currRoundStart <- perasRoundStart currRoundNo
  -- Minimum number of slots to consider before the candidate block
  let _L = SlotNo (unPerasBlockMinSlots blockMinSlots)
  -- Determine the candidate slot horizon
  -- NOTE: here we need make sure that the result doesn't underflow
  let candidateSlotHorizon
        | currRoundStart >= _L = currRoundStart - _L
        | otherwise = SlotNo 0
  -- Split the chain at the candidate slot horizon
  pure $ fst $ AF.splitAtSlot candidateSlotHorizon currChain
```
