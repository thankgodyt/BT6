### Title
Shelley `ledgerViewForecastAt` Anchors Forecast at Ledger Tip Instead of First Unknown Header, Reducing Effective Maximum Rollback to k-1 — (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/SupportsProtocol.hs`)

---

### Summary

The Shelley `ledgerViewForecastAt` implementation anchors its forecast range at the current ledger tip (the chain-sync intersection point) rather than at the first unknown header from the peer. Because the stability window is measured from the wrong anchor, the forecast only guarantees that `k` peer headers can be validated, not the required `k+1`. This reduces the effective maximum rollback in all Shelley-based eras from `k` to `k-1`. An unprivileged peer serving a valid chain that is exactly `k+1` blocks longer than the local chain can cause the honest node to silently fail to adopt the canonical chain, leaving it permanently on a shorter, less-secure fork.

---

### Finding Description

The analog vulnerability class from the external report is: **state committed at time T is used to authorize actions at time T+N without verifying that the state is still current**. In Ouroboros Consensus the equivalent is: the `LedgerView` (stake distribution snapshot) produced by `ledgerViewForecastAt` is derived from the ledger state at the intersection point — which may be up to `k` blocks in the past — and the forecast horizon is computed from that stale anchor, making it too short to cover all headers the ChainSync client must validate.

**Root cause in code:**

`ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/SupportsProtocol.hs`, lines 50–78:

```haskell
ledgerViewForecastAt cfg ledgerState = Forecast at $ \for ->
  if
    | NotOrigin for == at ->
        return $ SL.currentLedgerView shelleyLedgerState
    | for < maxFor ->
        return $ futureLedgerView for
    | otherwise ->
        throwError $ OutsideForecastRange { ... }
 where
  ...
  at = ledgerTipSlot ledgerState   -- intersection point

  -- Exclusive upper bound
  maxFor :: SlotNo
  maxFor = addSlots swindow $ succWithOrigin at   -- anchored at tip+1
```

`maxFor` is `at + 1 + swindow`. The forecast is therefore anchored at the slot immediately after the intersection tip. The Honest Chain Growth (HCG) property guarantees that `swindow = 3k/f` slots contain at least `k` blocks. Because the anchor is the intersection tip (not the first unknown header), the `swindow`-slot window covers at most `k` of the peer's headers. The node needs `k+1` headers to confirm the peer's chain is longer; the `(k+1)`th header falls outside `maxFor`.

The technical report explicitly documents this misalignment:

> *"Due to a misalignment between the consensus requirements and the Shelley specification, this is not the case for Shelley, where the effective maximum rollback is in fact k−1; see §shelley:forecasting."*
> — `docs/tech-reports/report/chapters/consensus/ledger.tex`, lines 325–329

And the future-work section identifies the correct fix:

> *"In chain sync we do not currently take advantage of the knowledge of the location of header B. We should change this. By anchoring the stability window at the last known block, we only have a guarantee that we can validate k headers, but we should really be able to validate k+1 headers … If we anchored the stability window after the first unknown header, where it should be anchored, we can validate k headers after the first unknown header, and hence k+1 in total."*
> — `docs/tech-reports/report/chapters/future/lowdensity.tex`, lines 287–295

The ChainSync client's `projectLedgerView` (called from `checkTime`) calls `ledgerViewForecastAt` on the raw intersection ledger state without first ticking to the first unknown header:

```haskell
projectLedgerView slot lst =
  let forecast = ledgerViewForecastAt (configLedger cfg) lst
  in case runExcept $ forecastFor forecast slot of
       Right ledgerView -> Just ledgerView
       Left OutsideForecastRange{} -> Nothing
```
— `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`, lines 1865–1878

When `forecastFor` returns `Nothing` (outside range), the client blocks waiting for the local chain to advance. If the `(k+1)`th header is permanently outside the forecast range, the client never unblocks and the node never switches to the longer chain.

---

### Impact Explanation

**Impact class: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

The Ouroboros security model requires that a node can always switch to any chain that is strictly longer than its own, up to a rollback of `k` blocks. With the effective rollback reduced to `k-1`, a node that has `k` blocks after the intersection cannot validate the `(k+1)`th header of a competing chain. It therefore fails to adopt the canonical chain and remains permanently on a shorter fork. This violates the Common Prefix and Chain Growth properties that underpin Ouroboros safety.

---

### Likelihood Explanation

**Likelihood: Medium.**

The scenario requires the intersection to be exactly `k` blocks back and the peer's chain to be exactly `k+1` blocks longer. This boundary condition arises naturally during network partitions, when a node reconnects after being offline, or when an adversary deliberately constructs a chain of exactly `k+1` blocks after the intersection. No stake majority is required; the adversary only needs to serve a valid chain (which may have been produced by honest nodes on the other side of a partition). The `hard_won_wisdom.md` test-infrastructure comment at `Test/ThreadNet/Infra/TwoEras.hs` lines 181–221 explicitly caps partition durations at `2k-2` slots to avoid triggering exactly this failure mode, confirming the scenario is reachable in practice.

---

### Recommendation

Anchor the forecast at the **first unknown header's slot** rather than at the intersection tip. Concretely, extend `LedgerSupportsProtocol` with a variant of `ledgerViewForecastAt` that accepts a ticked ledger state (ticked to the first unknown header's slot), and use that in the ChainSync client. The future-work section of the technical report (`lowdensity.tex`, footnote 288) already describes this fix:

> *"Concretely, we would have to extend the `LedgerSupportsProtocol` class with a function that forecasts the ledger view given a ticked ledger state."*

This would shift `maxFor` to `firstUnknownHeaderSlot + swindow`, which by HCG guarantees `k` blocks after the first unknown header, giving `k+1` total — restoring the intended security parameter.

---

### Proof of Concept

1. Node A has local chain C₁ with `k` blocks after intersection point B₀ (tip slot `s`).
2. Peer P advertises chain C₂ forking at B₀ with `k+1` blocks after B₀.
3. Node A calls `ledgerViewForecastAt cfg (ledgerStateAt B₀)`.
4. `maxFor = s + 1 + swindow`. By HCG, C₂'s `k`th block is at slot ≤ `s + swindow`; its `(k+1)`th block is at slot > `s + swindow` (outside `maxFor`).
5. `projectLedgerView (slotOf C₂[k+1]) lst` returns `Nothing`.
6. The ChainSync client blocks on `readLedgerState`, waiting for the local chain to advance past B₀. But Node A's chain C₁ has only `k` blocks after B₀ — it never advances the intersection far enough to bring C₂[k+1] into forecast range.
7. Node A never switches to C₂ and remains on the shorter chain C₁, violating the longest-chain rule. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/SupportsProtocol.hs (L50-78)
```haskell
  ledgerViewForecastAt cfg ledgerState = Forecast at $ \for ->
    if
      | NotOrigin for == at ->
          return $ SL.currentLedgerView shelleyLedgerState
      | for < maxFor ->
          return $ futureLedgerView for
      | otherwise ->
          throwError $
            OutsideForecastRange
              { outsideForecastAt = at
              , outsideForecastMaxFor = maxFor
              , outsideForecastFor = for
              }
   where
    ShelleyLedgerState{shelleyLedgerState} = ledgerState
    globals = shelleyLedgerGlobals cfg
    swindow = SL.stabilityWindow globals
    at = ledgerTipSlot ledgerState

    futureLedgerView :: SlotNo -> SL.LedgerView
    futureLedgerView =
      either
        (\e -> error ("futureLedgerView failed: " <> show e))
        id
        . SL.futureLedgerView globals shelleyLedgerState

    -- Exclusive upper bound
    maxFor :: SlotNo
    maxFor = addSlots swindow $ succWithOrigin at
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1707-1733)
```haskell
checkTime ::
  forall m blk arrival judgment.
  ( IOLike m
  , LedgerSupportsProtocol blk
  ) =>
  ConfigEnv m blk ->
  DynamicEnv m blk ->
  InternalEnv m blk arrival judgment ->
  KnownIntersectionState blk ->
  arrival ->
  SlotNo ->
  m (UpdatedIntersectionState blk (LedgerView (BlockProtocol blk), RelativeTime))
checkTime cfgEnv dynEnv intEnv =
  \kis arrival slotNo -> pauseBucket $ castEarlyExitIntersects $ do
    Intersects kis2 (lst, slotTime) <- checkArrivalTime kis arrival
    Intersects kis3 ledgerView <- case projectLedgerView slotNo lst of
      Just ledgerView -> pure $ Intersects kis2 ledgerView
      Nothing -> do
        EarlyExit.lift $
          traceWith (tracer cfgEnv) $
            TraceWaitingBeyondForecastHorizon slotNo
        res <- readLedgerState kis2 (projectLedgerView slotNo)
        EarlyExit.lift $
          traceWith (tracer cfgEnv) $
            TraceAccessingForecastHorizon slotNo
        pure res
    pure $ Intersects kis3 (ledgerView, slotTime)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1859-1878)
```haskell
  -- Returns 'Nothing' if the ledger state cannot forecast the ledger view
  -- that far into the future.
  projectLedgerView ::
    SlotNo ->
    LedgerState blk EmptyMK ->
    Maybe (LedgerView (BlockProtocol blk))
  projectLedgerView slot lst =
    let forecast = ledgerViewForecastAt (configLedger cfg) lst
     in -- TODO cache this in the KnownIntersectionState? Or even in the
        -- LedgerDB?

        case runExcept $ forecastFor forecast slot of
          Right ledgerView -> Just ledgerView
          Left OutsideForecastRange{} ->
            -- The header is too far ahead of the intersection point with
            -- our current chain. We have to wait until our chain and the
            -- intersection have advanced far enough. This will wait on
            -- changes to the current chain via the call to
            -- 'intersectsWithCurrentChain' before it.
            Nothing
```

**File:** docs/tech-reports/report/chapters/consensus/ledger.tex (L322-329)
```tex
$k + 1$ headers in order to adopt the alternative chain. However, the range of a
forecast is based on \emph{slots}, not blocks; since not every slot may contain
a block (\cref{time:slots-vs-blocks}), the range needs to be sufficient to
\emph{guarantee} to contain at least $k + 1$ blocks\footnote{Due to a
misalignment between the consensus requirements and the Shelley specification,
this is not the case for Shelley, where the effective maximum rollback is in
fact $k - 1$; see \cref{shelley:forecasting}).}; we will come back to this in
\cref{future:block-vs-slot}.
```

**File:** docs/tech-reports/report/chapters/future/lowdensity.tex (L287-295)
```tex
In chain sync we do not currently take advantage of the knowledge of the
location of header $B$.\footnote{\label{footnote:anchor-after-first-header}We
should change this. By anchoring the stability window at the last known block,
we only have a guarantee that we can validate $k$ headers, but we should really
be able to validate $k + 1$ headers in order to get a chain that is longer than
our own (\cref{low-density:tension}). If we anchored the stability window after
the first unknown header, where it \emph{should} be anchored, we can validate
$k$ headers \emph{after} the first unknown header, and hence $k + 1$ in total.
Concretely, we would have to extend the \lstinline!LedgerSupportsProtocol! class
```

**File:** docs/tech-reports/report/chapters/appendix/shelley.tex (L85-89)
```tex
\section{Forecasting}
\label{shelley:forecasting}

Discuss the fact that the effective maximum rollback in Shelley is $k - 1$,
not $k$; see also \cref{ledger:forecasting}.
```
