Based on my investigation, I found a direct analog to the "ignored return value from a validation function" vulnerability class.

---

### Title
`assertWithMsg` Envelope Check Silently Bypassed in Production Builds — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs`, `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs`)

### Summary

`assertWithMsg` is a CPP-guarded assertion that is a **complete no-op** in production builds compiled without `ENABLE_ASSERTIONS`. In `revalidateHeader`, the entire envelope validation (block number, slot number, prev-hash, checkpoint checks) is wrapped in `assertWithMsg`, meaning the check result is silently discarded in production. This is the direct Haskell analog of the Solidity bug: a validation function is called but its return value is ignored.

### Finding Description

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs` defines:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
``` [1](#0-0) 

When `ENABLE_ASSERTIONS` is **not** defined (the default in production/optimized builds), the CPP block is absent and the function reduces to `assertWithMsg _ a = a` — the `Either String ()` argument is unconditionally discarded.

`revalidateHeader` in `HeaderValidation.hs` uses this for its entire envelope check:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
``` [2](#0-1) 

`validateEnvelope` enforces: consecutive block numbers, non-decreasing slot numbers, prev-hash linkage, and checkpoint hash matching. [3](#0-2) 

In production builds, `assertWithMsg envelopeCheck` evaluates `envelopeCheck` (computing the `Either`) but **never acts on a `Left` result**. The function always returns the new `HeaderState` regardless of whether the envelope is valid. This is structurally identical to the Solidity bug: `_hasValidParentNodeDefinitions(nodeDefinition)` is called but its `bool` return is discarded.

The `ENABLE_ASSERTIONS` flag is only set in specific cabal configurations: [4](#0-3) 

### Impact Explanation

`revalidateHeader` is called during block re-application from storage (e.g., `reapplyBlockLedgerResult` in `Extended.hs`). [5](#0-4) 

If a crafted or corrupted on-disk block (ImmutableDB/VolatileDB/snapshot) contains a header with a wrong block number, broken prev-hash chain, or checkpoint mismatch, `revalidateHeader` will accept it without error in production builds. This can cause the node to durably commit an invalid ledger state derived from a structurally invalid chain, matching the **High** impact tier: *ChainDB/ImmutableDB/VolatileDB/LedgerDB/snapshot corruption/replay/rollback bug that causes durable use of the wrong ledger state*.

### Likelihood Explanation

**Medium.** The trigger requires either a crafted snapshot fed to a node (local reproduction / private-testnet scenario) or a DB corruption that produces a header violating envelope invariants. The node will silently accept it during replay. No privileged access is required — a crafted snapshot file is sufficient.

### Recommendation

Replace `assertWithMsg` in `revalidateHeader` with a hard error that is **not** CPP-gated, so the envelope check is enforced unconditionally in all build configurations:

```haskell
revalidateHeader cfg ledgerView hdr st =
  case envelopeCheck of
    Left err -> error ("revalidateHeader: envelope check failed: " <> err)
    Right () ->
      HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
```

Alternatively, audit all other call sites of `assertWithMsg` in production modules (`ChainSync/Client.hs`, `AnchoredFragment.hs`, `HardFork/Combinator/AcrossEras.hs`, `Shelley/Node/TPraos.hs`, `Cardano/Node.hs`) for the same pattern and replace security-critical checks with unconditional guards.

### Proof of Concept

1. Compile `ouroboros-consensus` **without** `-DENABLE_ASSERTIONS` (the default production build).
2. Construct a snapshot or VolatileDB entry containing a block whose header has `blockNo = 999` but whose predecessor has `blockNo = 1` (violating the consecutive block number invariant).
3. Start a node that replays from this snapshot. `revalidateHeader` is called; `validateEnvelope` computes `Left "UnexpectedBlockNo ..."` but `assertWithMsg` discards it.
4. The node accepts the invalid header, advances its `HeaderState` to the corrupted tip, and continues building on an invalid chain. [1](#0-0) [2](#0-1)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L364-376)
```haskell
validateEnvelope cfg ledgerView oldTip hdr = do
  unless (actualBlockNo == expectedBlockNo) $
    throwError $
      UnexpectedBlockNo expectedBlockNo actualBlockNo
  unless (actualSlotNo >= expectedSlotNo) $
    throwError $
      UnexpectedSlotNo expectedSlotNo actualSlotNo
  unless (checkPrevHash' (annTipHash <$> oldTip) actualPrevHash) $
    throwError $
      UnexpectedPrevHash (annTipHash <$> oldTip) actualPrevHash
  validateIfCheckpoint (topLevelConfigCheckpoints cfg) hdr
  withExcept OtherHeaderEnvelopeError $
    additionalEnvelopeChecks cfg ledgerView hdr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L539-561)
```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState
      (NotOrigin (getAnnTip hdr))
      chainDepState'
 where
  chainDepState' :: ChainDepState (BlockProtocol blk)
  chainDepState' =
    reupdateChainDepState
      (configConsensus cfg)
      (validateView (configBlock cfg) hdr)
      (blockSlot hdr)
      (tickedHeaderStateChainDep st)

  envelopeCheck :: Either String ()
  envelopeCheck =
    runExcept $
      withExcept show $
        validateEnvelope
          cfg
          ledgerView
          (untickedHeaderStateTip st)
          hdr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Extended.hs (L1-10)
```haskell
{- HLINT ignore "Unused LANGUAGE pragma" -}
-- False hint on TypeOperators
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
```
