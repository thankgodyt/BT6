### Title
Incorrect `MaxMajorProtVer` for Development Mode Causes Dijkstra-Era Blocks to Be Rejected as `ObsoleteNode` - (`File: ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Cardano.hs`)

### Summary

In `Cardano/Node/Protocol/Cardano.hs`, the `cardanoProtocolVersion` field (which sets `MaxMajorProtVer`) is hardcoded to `ProtVer (natVersion @11) 0` when `npcTestEnableDevelopmentHardForkEras` is `True`. However, the Dijkstra era uses protocol major version **12**, not 11. Because `MaxMajorProtVer` is derived directly from this value and is used in the Praos envelope check to reject blocks whose ledger state has a protocol version exceeding the configured maximum, any node with development mode enabled will reject all valid Dijkstra-era blocks with an `ObsoleteNode` error, preventing it from ever following the Dijkstra chain.

### Finding Description

The `cardanoProtocolVersion` field of `CardanoProtocolParams` serves two purposes: it is included in forged block headers as a signal, and — critically — its major component becomes the `MaxMajorProtVer` used in the Praos envelope check.

In `protocolInfoCardano` (called from `mkSomeConsensusProtocolCardano`), the value is set as:

```haskell
-- IMPORTANT: this Protver below has to be kept in sync with the values
-- used in the node in cardano-node/src/Cardano/Node/Protocol/Cardano.hs
-- in function mkSomeConsensusProtocolCardano.
( if npcTestEnableDevelopmentHardForkEras
    then ProtVer (natVersion @11) 0   -- BUG: should be @12
    else ProtVer (natVersion @10) 7
)
``` [1](#0-0) 

The same source file documents the protocol version table in a comment:

```
-- Version 9  is Conway
-- Version 10 is Conway (intra era hardfork)
-- Version 11 is Conway (intra era hardfork)
-- Version 12 is Dijkstra
``` [2](#0-1) 

The `MaxMajorProtVer` is derived directly from `cardanoProtocolVersion`:

```haskell
maxMajorProtVer :: MaxMajorProtVer
maxMajorProtVer = MaxMajorProtVer $ pvMajor cardanoProtocolVersion
``` [3](#0-2) 

This `maxMajorProtVer` is then passed to both `tpraosParams` and `praosParams`: [4](#0-3) 

The Praos envelope check in `Ouroboros.Consensus.Shelley.Protocol.Praos` then enforces:

```haskell
envelopeChecks cfg lv hdr = do
    unless (m <= maxpv) $ throwError (ObsoleteNode m maxpv)
```

where `m` is the protocol major version from the ticked ledger view and `maxpv` is `MaxMajorProtVer`. [5](#0-4) 

When the chain transitions to Dijkstra (ledger protocol version 12), `m = 12 > maxpv = 11`, so every Dijkstra header is rejected with `ObsoleteNode 12 11`, even though the operator explicitly enabled development hard fork eras to participate in Dijkstra testing.

### Impact Explanation

A node running with `npcTestEnableDevelopmentHardForkEras = True` on a private Dijkstra testnet will reject every Dijkstra-era block header received from any peer via ChainSync. The node cannot advance its chain past the Conway→Dijkstra transition, causing it to permanently diverge from the Dijkstra chain. This breaks cross-era consensus for all nodes using this code path to test the Dijkstra era, matching the "Hard-fork, era transition mismatch that breaks cross-era consensus" impact class.

### Likelihood Explanation

Any node operator who sets `npcTestEnableDevelopmentHardForkEras = True` — the exact flag documented as required for Dijkstra testnet participation — will trigger this bug the moment the chain reaches the Dijkstra era. The trigger is simply receiving a valid Dijkstra block header from an unprivileged peer. No special attacker capability is required; the bug fires automatically on any conforming Dijkstra chain.

### Recommendation

Change the development-mode `ProtVer` constant from `natVersion @11` to `natVersion @12` to match the Dijkstra era's actual protocol major version:

```haskell
( if npcTestEnableDevelopmentHardForkEras
    then ProtVer (natVersion @12) 0   -- Dijkstra
    else ProtVer (natVersion @10) 7
)
```

Additionally, the comment in `CardanoProtocolParams` already warns that this value "has to be kept in sync" with `cardano-node`. A compile-time assertion or automated derivation from `L.eraProtVerLow @DijkstraEra` (as used in `toTriggerHardFork`) would prevent this class of off-by-one error from recurring.

### Proof of Concept

1. Build a private testnet with `npcTestEnableDevelopmentHardForkEras = True` and `npcTestDijkstraHardForkAtEpoch = Just <some_epoch>`.
2. Let the chain reach the configured Dijkstra epoch.
3. Observe that every node rejects incoming Dijkstra headers with `ObsoleteNode 12 11` from `envelopeChecks` in `Ouroboros.Consensus.Shelley.Protocol.Praos`.
4. The chain halts at the Conway→Dijkstra boundary; no node can extend the Dijkstra chain.

The root cause is the single hardcoded literal `natVersion @11` at line 256 of `Cardano/Node/Protocol/Cardano.hs`, which should be `natVersion @12` to match the Dijkstra era's protocol major version as documented in the version table at lines 198–210 of the same file. [6](#0-5)

### Citations

**File:** ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Cardano.hs (L198-210)
```haskell
                -- Version 0 is Byron with Ouroboros classic
                -- Version 1 is Byron with Ouroboros Permissive BFT
                -- Version 2 is Shelley
                -- Version 3 is Allegra
                -- Version 4 is Mary
                -- Version 5 is Alonzo
                -- Version 6 is Alonzo (intra era hardfork)
                -- Version 7 is Babbage
                -- Version 8 is Babbage (intra era hardfork)
                -- Version 9 is Conway
                -- Version 10 is Conway (intra era hardfork)
                -- Version 11 is Conway (intra era hardfork)
                -- Version 12 is Dijkstra
```

**File:** ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Cardano.hs (L252-258)
```haskell
        -- IMPORTANT: this Protver below has to be kept in sync with the values
        -- used in the node in cardano-node/src/Cardano/Node/Protocol/Cardano.hs
        -- in function mkSomeConsensusProtocolCardano.
        ( if npcTestEnableDevelopmentHardForkEras
            then ProtVer (natVersion @11) 0
            else ProtVer (natVersion @10) 7
        )
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L640-641)
```haskell
  maxMajorProtVer :: MaxMajorProtVer
  maxMajorProtVer = MaxMajorProtVer $ pvMajor cardanoProtocolVersion
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L670-686)
```haskell
  tpraosParams :: TPraosParams
  tpraosParams =
    Shelley.mkTPraosParams
      maxMajorProtVer
      initialNonceShelley
      genesisShelley

  TPraosParams{tpraosSlotsPerKESPeriod, tpraosMaxKESEvo} = tpraosParams

  praosParams :: PraosParams
  praosParams =
    PraosParams
      { praosSlotsPerKESPeriod = SL.sgSlotsPerKESPeriod genesisShelley
      , praosLeaderF = SL.mkActiveSlotCoeff $ SL.sgActiveSlotsCoeff genesisShelley
      , praosSecurityParam = SecurityParam $ SL.sgSecurityParam genesisShelley
      , praosMaxKESEvo = SL.sgMaxKESEvolutions genesisShelley
      , praosMaxMajorPV = maxMajorProtVer
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Praos.hs (L111-122)
```haskell
  envelopeChecks cfg lv hdr = do
    unless (m <= maxpv) $ throwError (ObsoleteNode m maxpv)
    unless (bhviewHSize bhv <= fromIntegral @Word16 @Int maxHeaderSize) $
      throwError $
        HeaderSizeTooLarge (bhviewHSize bhv) maxHeaderSize
    unless (bhviewBSize bhv <= maxBodySize) $
      throwError $
        BlockSizeTooLarge (bhviewBSize bhv) maxBodySize
   where
    pp = praosParams cfg
    (MaxMajorProtVer maxpv) = praosMaxMajorPV pp
    (ProtVer m _) = lvProtocolVersion lv
```
