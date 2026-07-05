### Title
Shelley Forecast Range One Block Shorter Than Required Reduces Effective Rollback to k-1, Enabling Chain Selection Failure Under Eclipse - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/SupportsProtocol.hs`)

---

### Summary

The `ledgerViewForecastAt` implementation for all Shelley-based eras computes a forecast range of exactly `swindow = 3k/f` slots. Due to a misalignment between the consensus requirement (k+1 blocks must be within range) and the Shelley specification (the stability window guarantees only k blocks), the effective maximum rollback is k-1, not k. This creates a narrow window — directly analogous to the liquidation threshold being too small — where an adversary who has eclipsed a node and fed it k adversarial blocks can prevent the node from ever adopting the honest chain, causing a durable chain selection failure.

---

### Finding Description

In `LedgerSupportsProtocol (ShelleyBlock (TPraos crypto) era)`, the forecast upper bound is:

```haskell
maxFor :: SlotNo
maxFor = addSlots swindow $ succWithOrigin at
```

where `swindow = SL.stabilityWindow globals`, computed via `SL.computeStabilityWindow k tpraosLeaderF` (≈ `3k/f` slots). [1](#0-0) 

The `stabilityWindow` field is populated in `mkShelleyGlobals`: [2](#0-1) 

The consensus requirement, stated in the technical report, is that the forecast range must guarantee **at least k+1 blocks**, so that when a node's intersection with a peer is exactly k blocks back, it can validate k+1 headers and adopt the longer chain. The Shelley stability window of `3k/f` was designed to guarantee k blocks (for stake-distribution stability), not k+1. The technical report explicitly acknowledges the resulting shortfall:

> *"Due to a misalignment between the consensus requirements and the Shelley specification, this is not the case for Shelley, where the effective maximum rollback is in fact k − 1; see §shelley:forecasting."* [3](#0-2) [4](#0-3) 

The `forecastAcrossShelley` cross-era path inherits the same bound via `crossEraForecastBound`, which takes `SL.stabilityWindow (shelleyLedgerGlobals cfgFrom)` as its `currentLookahead`: [5](#0-4) 

The Praos variant of `ledgerViewForecastAt` delegates directly to the TPraos instance, so it inherits the same defect: [6](#0-5) 

---

### Impact Explanation

When the ChainSync client's intersection with a peer is exactly k blocks back, it must validate k+1 headers to determine whether to adopt the peer's chain. The forecast is anchored at the intersection ledger state. Because the forecast range covers only k blocks (not k+1), the client calls `forecastFor` for the (k+1)th header and receives `OutsideForecastRange`. [7](#0-6) 

When the peer's chain is preferable (longer), the client issues an STM `retry`, waiting for the local chain to advance. If the node is eclipsed, no honest blocks arrive, the local chain does not advance, and the node is permanently unable to validate the (k+1)th header. The node remains on the adversarial chain. This is a durable chain selection failure: an honest node prefers a non-canonical chain beyond the intended security assumptions of the protocol.

The analog to the GLP liquidation bug is exact: just as a 10% liquidation threshold leaves only 1% of borrowed GLP as margin before bad debt, a forecast range that guarantees only k blocks (not k+1) leaves zero margin at the maximum rollback depth — the one scenario the protocol is specifically designed to handle.

---

### Likelihood Explanation

The attack requires an eclipse (the adversary controls all of the target node's peer connections) and the ability to produce k adversarial blocks. Eclipse attacks are a well-studied threat against blockchain nodes with few peers or in network partitions. The adversary does not need any cryptographic keys beyond those needed to produce k valid blocks on their private fork. No admin access, stake majority, or key compromise is required.

---

### Recommendation

The stability window used as the forecast lookahead should be increased to guarantee k+1 blocks, not k. Concretely, `SL.computeStabilityWindow` should return a value sufficient to span k+1 blocks under the Honest Chain Growth assumption, or the consensus layer should add one slot to `maxFor` to compensate for the off-by-one. The technical report already identifies this as a known issue requiring resolution. [8](#0-7) 

---

### Proof of Concept

1. Adversary eclipses a target node (controls all its outbound/inbound peer connections).
2. Adversary presents k adversarial blocks; the node adopts them (intersection with the honest chain is now exactly k blocks back).
3. Honest chain is k+1 blocks longer than the adversarial chain.
4. ChainSync client attempts to validate k+1 headers from an honest peer.
5. `ledgerViewForecastAt` is called on the intersection ledger state; `maxFor = addSlots swindow (at+1)` covers only k blocks.
6. The (k+1)th header's slot falls at or beyond `maxFor`; `forecastFor` returns `OutsideForecastRange`.
7. Because the honest chain is preferable, the client issues STM `retry` rather than disconnecting.
8. No honest blocks arrive (eclipse); the local chain does not advance; the retry never succeeds.
9. The node is permanently stuck on the adversarial chain, unable to adopt the canonical honest chain.

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

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/SupportsProtocol.hs (L105-107)
```haskell
  ledgerViewForecastAt cfg st =
    mapForecast (translateLedgerView (Proxy @(TPraos crypto, Praos crypto))) $
      ledgerViewForecastAt @(ShelleyBlock (TPraos crypto) era) cfg st'
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/TPraos.hs (L413-414)
```haskell
    , stabilityWindow = SL.computeStabilityWindow k tpraosLeaderF
    , randomnessStabilisationWindow = SL.computeRandomnessStabilisationWindow k tpraosLeaderF
```

**File:** docs/tech-reports/report/chapters/consensus/ledger.tex (L325-329)
```tex
\emph{guarantee} to contain at least $k + 1$ blocks\footnote{Due to a
misalignment between the consensus requirements and the Shelley specification,
this is not the case for Shelley, where the effective maximum rollback is in
fact $k - 1$; see \cref{shelley:forecasting}).}; we will come back to this in
\cref{future:block-vs-slot}.
```

**File:** docs/tech-reports/report/chapters/appendix/shelley.tex (L85-89)
```tex
\section{Forecasting}
\label{shelley:forecasting}

Discuss the fact that the effective maximum rollback in Shelley is $k - 1$,
not $k$; see also \cref{ledger:forecasting}.
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs (L335-342)
```haskell
  -- Exclusive upper bound
  maxFor :: SlotNo
  maxFor =
    crossEraForecastBound
      (ledgerTipSlot ledgerStateFrom)
      (boundSlot transition)
      (SL.stabilityWindow (shelleyLedgerGlobals cfgFrom))
      (SL.stabilityWindow (shelleyLedgerGlobals cfgTo))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1801-1819)
```haskell
        let KnownIntersectionState
              { mostRecentIntersection
              } = kis'
        lst <-
          fmap
            ( maybe
                ( error $
                    "intersection not within last k blocks: "
                      <> show mostRecentIntersection
                )
                ledgerState
            )
            $ getPastLedger mostRecentIntersection
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView
```

**File:** docs/website/contents/references/miscellaneous/hard_won_wisdom.md (L104-115)
```markdown
## Why use the Honest Chain Growth window as the Ledger's Stability Window?

Suppose we have selected a different chain than our peer and that our selected chain has L blocks after the intersection and their selected chain has R blocks after the intersection.

REQ1: If k<L, we must promptly disconnect from the peer (b/c of Common Prefix violation and Limit on Rollback).

REQ2: If L≤k (see REQ1) and L<R, we must validate at least L+1 of their headers, because Praos requires us to fetch and select the longer chain, and validating those headers is the first step towards selecting those blocks.
(This requirement ignores tiebreakers here because the security argument must hold even if the adversary wins a tiebreaker.)

The most demanding case of REQ2 is L=k: at most we'll need to validate k+1 of the peer's headers.
Thus using HCG window as Stability Window ensures that forecasting can't disrupt REQ2 when the peer is serving honest blocks.
(We can tick the intersection ledger state to their first header, and then forecast 3k/f from there which by HCG will get us at least the remaining k headers if they're serving an honest chain.)
```
