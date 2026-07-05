### Title
`protocolInfoCardano` Hardcodes `TriggerHardForkNotDuringThisExecution` for Conway→Dijkstra Transition, Silently Ignoring `triggerHardForkDijkstra` - (File: `ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs`)

---

### Summary

In `protocolInfoCardano`, the `triggerHardForkDijkstra` field is omitted from the `CardanoHardForkTriggers'` pattern match, and `partialLedgerConfigConway` is hardcoded to use `TriggerHardForkNotDuringThisExecution` instead of `toTriggerHardFork triggerHardForkDijkstra`. This means the Conway→Dijkstra era transition can never occur within any running node process, regardless of what the on-chain ledger state dictates. Every other era correctly passes its configured trigger to the next era's ledger config; Conway alone is hardcoded to block the transition.

---

### Finding Description

The `CardanoHardForkTriggers'` pattern exposes seven fields — one per Shelley-based era transition — including `triggerHardForkDijkstra`: [1](#0-0) 

In `protocolInfoCardano`, the `where`-clause destructures `cardanoHardForkTriggers` using `CardanoHardForkTriggers'` but **omits `triggerHardForkDijkstra`**: [2](#0-1) 

Because `triggerHardForkDijkstra` is never bound, it is silently discarded. Then `partialLedgerConfigConway` is constructed with a hardcoded `TriggerHardForkNotDuringThisExecution` instead of `toTriggerHardFork triggerHardForkDijkstra`: [3](#0-2) 

Compare with every other era, which correctly threads its trigger through: [4](#0-3) 

`TriggerHardForkNotDuringThisExecution` causes `singleEraTransition` for the Conway `SingleEraBlock` instance to always return `Nothing`: [5](#0-4) 

A `Nothing` result means the HFC never produces `TransitionKnown` for the Conway era, so `reconstructSummaryLedger` never advances the HFC telescope past Conway, and the node never enters the Dijkstra era.

The Dijkstra era itself is correctly set to `TriggerHardForkNotDuringThisExecution` (it is the final era): [6](#0-5) 

The Conway config should mirror the Babbage→Conway pattern but instead mirrors the Dijkstra (terminal) pattern.

---

### Impact Explanation

When the Dijkstra hard fork is triggered on-chain (protocol version 12 by default, or a test epoch override), the ledger state will reflect the transition, but every node built with this `protocolInfoCardano` will have `singleEraTransition @Conway` permanently returning `Nothing`. The HFC will never advance to Dijkstra. The node will reject all Dijkstra-era blocks as `HardForkLedgerErrorWrongEra` / `HardForkValidationErrWrongEra`, diverge from the canonical chain, and be unable to participate in or validate the post-fork network. This is a **hard-fork era transition mismatch that breaks cross-era consensus for production Cardano nodes** — matching the "High" impact tier.

---

### Likelihood Explanation

This is a structural omission in the single canonical `protocolInfoCardano` function used by all Cardano nodes. It affects every node unconditionally once the Dijkstra hard fork is activated on any network (mainnet, preview, preprod, or a private testnet using `CardanoTriggerHardForkAtDefaultVersion`). No special attacker action is required; the chain's own governance process is the trigger. Likelihood is **High**.

---

### Recommendation

1. Add `triggerHardForkDijkstra` to the `CardanoHardForkTriggers'` pattern match in `protocolInfoCardano`:

```haskell
cardanoHardForkTriggers =
  CardanoHardForkTriggers'
    { triggerHardForkShelley
    , triggerHardForkAllegra
    , triggerHardForkMary
    , triggerHardForkAlonzo
    , triggerHardForkBabbage
    , triggerHardForkConway
    , triggerHardForkDijkstra   -- add this
    }
```

2. Replace the hardcoded `TriggerHardForkNotDuringThisExecution` in `partialLedgerConfigConway` with the configured trigger:

```haskell
partialLedgerConfigConway =
  mkPartialLedgerConfigShelley
    transitionConfigConway
    (toTriggerHardFork triggerHardForkDijkstra)  -- was TriggerHardForkNotDuringThisExecution
```

---

### Proof of Concept

**Attacker-controlled entry path:** An unprivileged peer serving valid Dijkstra-era headers/blocks to a node running this code. The node's ChainSync client calls `ledgerViewForecastAt`, which calls `singleEraTransition` on the Conway ledger state. Because `shelleyTriggerHardFork` is `TriggerHardForkNotDuringThisExecution`, `singleEraTransition` returns `Nothing`, the HFC summary never includes the Dijkstra era, and `forecastFor` returns `OutsideForecastRange` for any slot in the Dijkstra era. The ChainSync client cannot validate Dijkstra headers, the node never selects the Dijkstra chain, and consensus diverges.

**Structural proof:**

- `CardanoHardForkTriggers'` has 7 fields including `triggerHardForkDijkstra`. [7](#0-6) 
- The pattern match in `protocolInfoCardano` binds only 6, omitting `triggerHardForkDijkstra`. [2](#0-1) 
- `partialLedgerConfigConway` uses `TriggerHardForkNotDuringThisExecution`. [3](#0-2) 
- `TriggerHardForkNotDuringThisExecution` → `singleEraTransition` returns `Nothing`. [5](#0-4) 
- `Nothing` → HFC never emits `TransitionKnown` for Conway → node never enters Dijkstra. [8](#0-7)

### Citations

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L490-518)
```haskell
pattern CardanoHardForkTriggers' ::
  c ~ StandardCrypto =>
  CardanoHardForkTrigger (ShelleyBlock (TPraos c) ShelleyEra) ->
  CardanoHardForkTrigger (ShelleyBlock (TPraos c) AllegraEra) ->
  CardanoHardForkTrigger (ShelleyBlock (TPraos c) MaryEra) ->
  CardanoHardForkTrigger (ShelleyBlock (TPraos c) AlonzoEra) ->
  CardanoHardForkTrigger (ShelleyBlock (Praos c) BabbageEra) ->
  CardanoHardForkTrigger (ShelleyBlock (Praos c) ConwayEra) ->
  CardanoHardForkTrigger (ShelleyBlock (Praos c) DijkstraEra) ->
  CardanoHardForkTriggers
pattern CardanoHardForkTriggers'
  { triggerHardForkShelley
  , triggerHardForkAllegra
  , triggerHardForkMary
  , triggerHardForkAlonzo
  , triggerHardForkBabbage
  , triggerHardForkConway
  , triggerHardForkDijkstra
  } =
  CardanoHardForkTriggers
    ( triggerHardForkShelley
        :* triggerHardForkAllegra
        :* triggerHardForkMary
        :* triggerHardForkAlonzo
        :* triggerHardForkBabbage
        :* triggerHardForkConway
        :* triggerHardForkDijkstra
        :* Nil
      )
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L604-612)
```haskell
    , cardanoHardForkTriggers =
      CardanoHardForkTriggers'
        { triggerHardForkShelley
        , triggerHardForkAllegra
        , triggerHardForkMary
        , triggerHardForkAlonzo
        , triggerHardForkBabbage
        , triggerHardForkConway
        }
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L797-801)
```haskell
  partialLedgerConfigBabbage :: PartialLedgerConfig (ShelleyBlock (Praos c) BabbageEra)
  partialLedgerConfigBabbage =
    mkPartialLedgerConfigShelley
      transitionConfigBabbage
      (toTriggerHardFork triggerHardForkConway)
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L816-820)
```haskell
  partialLedgerConfigConway :: PartialLedgerConfig (ShelleyBlock (Praos c) ConwayEra)
  partialLedgerConfigConway =
    mkPartialLedgerConfigShelley
      transitionConfigConway
      TriggerHardForkNotDuringThisExecution
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L835-839)
```haskell
  partialLedgerConfigDijkstra :: PartialLedgerConfig (ShelleyBlock (Praos c) DijkstraEra)
  partialLedgerConfigDijkstra =
    mkPartialLedgerConfigShelley
      transitionConfigDijkstra
      TriggerHardForkNotDuringThisExecution
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs (L243-244)
```haskell
    case shelleyTriggerHardFork pcfg of
      TriggerHardForkNotDuringThisExecution -> Nothing
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/CanHardFork.hs (L158-166)
```haskell
      , crossEraForecast =
          PCons crossEraForecastByronToShelleyWrapper $
            PCons crossEraForecastAcrossShelley $
              PCons crossEraForecastAcrossShelley $
                PCons crossEraForecastAcrossShelley $
                  PCons crossEraForecastAcrossShelley $
                    PCons crossEraForecastAcrossShelley $
                      PCons crossEraForecastAcrossShelley $
                        PNil
```
