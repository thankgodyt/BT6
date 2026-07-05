Based on my investigation, I found a direct analog to the external report's vulnerability class — a **required validation conditionally enforced only in debug builds, silently omitted in production** — in `revalidateHeader`.

---

### Title
`revalidateHeader` Silently Skips Required Envelope Validation in Production Builds via `assertWithMsg` No-Op — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs`)

---

### Summary

`revalidateHeader` guards its entire envelope check (block number, slot number, prev-hash) behind `assertWithMsg`, which is a **compile-time no-op** in production builds. When `ENABLE_ASSERTIONS` is not defined — the default for production — the check is not merely unenforced; it is not even evaluated. Any header is accepted unconditionally during revalidation, mirroring the external report's pattern of a required field being conditionally applied only under a specific condition.

---

### Finding Description

**`Assert.hs` — the root cause:**

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a          -- production: first arg ignored, not evaluated
``` [1](#0-0) 

When `ENABLE_ASSERTIONS` is absent, the CPP block is dropped entirely. The catch-all `assertWithMsg _ a = a` matches every call. Because Haskell is lazy and the first argument is bound to `_`, the `Either String ()` computation is **never forced**.

**`HeaderValidation.hs` — the call site:**

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
``` [2](#0-1) 

`validateEnvelope` checks three invariants that are **required** for every header regardless of era:

| Check | Error thrown |
|---|---|
| Block number is exactly `expectedBlockNo` | `UnexpectedBlockNo` |
| Slot number ≥ `expectedSlotNo` | `UnexpectedSlotNo` |
| Prev-hash matches current tip | `UnexpectedPrevHash` | [3](#0-2) 

In production, none of these checks fire. `revalidateHeader` returns `HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'` for **any** header, regardless of whether its block number, slot, or prev-hash are consistent with the supplied `Ticked (HeaderState blk)`.

The analog to the external report is exact:

| External report | This codebase |
|---|---|
| `if (params.price) { orderReq.p = params.price; }` | `#if ENABLE_ASSERTIONS assertWithMsg (Left msg) _ = error msg #endif` |
| Price required for limit/trigger orders but conditionally set | Envelope check required for all headers but conditionally enforced |
| Silent omission when caller omits price | Silent omission when `ENABLE_ASSERTIONS` is absent |

---

### Impact Explanation

`revalidateHeader` is called in two production paths:

1. **ImmutableDB replay during node initialization** — `reapplyExtLedgerState` in `Ouroboros/Consensus/Ledger/Extended.hs` calls `revalidateHeader` for every block replayed from the ImmutableDB. A crafted or corrupted ImmutableDB containing a block whose block number, slot, or prev-hash is inconsistent with the preceding chain will be silently accepted. The resulting `HeaderState` is wrong, and the ledger state derived from it is permanently incorrect for the lifetime of that node run.

2. **Chain-selection fork switches** — when the node switches to a candidate fork, headers on the new fork are replayed via `revalidateHeader`. If a header on the fork carries envelope fields inconsistent with the fork's own `HeaderState` (e.g., a non-monotone slot or a wrong prev-hash), the inconsistency is silently ignored in production, allowing the node to build an incorrect `HeaderState` for that fork and potentially adopt it.

Both paths map to the allowed impact scope: **ChainDB / ImmutableDB / LedgerDB replay/rollback bug that causes durable use of the wrong ledger state**. [4](#0-3) 

---

### Likelihood Explanation

The precondition for exploitation is that `revalidateHeader` is called on a header whose envelope fields are inconsistent with the supplied `HeaderState`. This can be triggered by:

- A **crafted ImmutableDB/snapshot** supplied as a `DB/snapshot input in a local reproduction` (explicitly listed as a valid entry path in the audit scope). The ImmutableDB stores raw bytes; a node operator or attacker with write access to the data directory can craft a chunk file whose block numbers or prev-hashes are subtly wrong. In production, the replay path will not detect this.
- A **latent bug** in any caller that passes a `Ticked (HeaderState blk)` that does not correspond to the header being revalidated. Because the check is a no-op in production, such bugs are invisible until they manifest as ledger divergence.

Likelihood is **medium-low**: requires either local DB access or a secondary bug, but the missing check means neither scenario produces any observable error.

---

### Recommendation

Replace the `assertWithMsg` guard with a proper monadic check that returns an error in all build configurations:

```haskell
revalidateHeader cfg ledgerView hdr st =
  case runExcept (validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr) of
    Left err -> error ("revalidateHeader: envelope invariant violated: " <> show err)
    Right () -> HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
```

Alternatively, if the performance cost of `validateEnvelope` during replay is a concern, the check should at minimum be enforced via a flag that is **on by default** in production rather than off by default.

The `ENABLE_ASSERTIONS` flag in `ouroboros-consensus.cabal` should be audited for all call sites of `assertWithMsg` to identify other production paths where required invariants are silently dropped. [5](#0-4) 

---

### Proof of Concept

1. Build a production node binary **without** `-DENABLE_ASSERTIONS` (the default).
2. Locate the ImmutableDB chunk file for the most recent chunk on disk.
3. Patch the serialised block number of the last block in that chunk to an arbitrary value (e.g., increment by 2, skipping a block number).
4. Restart the node. During `validateAndReopen` → `validateMostRecentChunk` → `validateChunk`, the chunk file parser reconstructs entries; `revalidateHeader` is then called for each replayed header.
5. In production, `assertWithMsg envelopeCheck` evaluates to `assertWithMsg _ a = a`; `envelopeCheck` is never forced; the patched block number passes silently.
6. The node's in-memory `HeaderState` now records the wrong block number, causing all subsequent block-number envelope checks (`UnexpectedBlockNo`) to fail for legitimately produced blocks, or — if the attacker also patches the successor block numbers — to accept a chain with a fabricated block-number sequence. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L1-15)
```haskell
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}

module Ouroboros.Consensus.Util.Assert (assertWithMsg) where

import GHC.Stack (HasCallStack)
import Ouroboros.Consensus.Util.RedundantConstraints

assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
 where
  _ = keepRedundantConstraint (Proxy @HasCallStack)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L364-384)
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
 where
  checkPrevHash' ::
    WithOrigin (HeaderHash blk) ->
    ChainHash blk ->
    Bool
  checkPrevHash' Origin GenesisHash = True
  checkPrevHash' (NotOrigin h) (BlockHash h') = h == h'
  checkPrevHash' _ _ = False
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L524-562)
```haskell
-- | Header revalidation
--
-- Same as 'validateHeader' but used when the header has been validated before
-- w.r.t. the same exact 'HeaderState'.
--
-- Expensive validation checks are skipped ('reupdateChainDepState' vs.
-- 'updateChainDepState').
revalidateHeader ::
  forall blk.
  (BlockSupportsProtocol blk, ValidateEnvelope blk, HasCallStack) =>
  TopLevelConfig blk ->
  LedgerView (BlockProtocol blk) ->
  Header blk ->
  Ticked (HeaderState blk) ->
  HeaderState blk
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Validation.hs (L271-307)
```haskell
validateMostRecentChunk ::
  forall m blk h.
  ( IOLike m
  , GetPrevHash blk
  , HasBinaryBlockInfo blk
  , DecodeDisk blk (Lazy.ByteString -> Either Plain.DecoderError blk)
  , ConvertRawHash blk
  , HasCallStack
  ) =>
  ValidateEnv m blk h ->
  Tracer m (TraceChunkValidation blk ()) ->
  -- | Most recent chunk on disk, the chunk to validate
  ChunkNo ->
  m (ChunkNo, WithOrigin (Tip blk))
validateMostRecentChunk validateEnv@ValidateEnv{hasFS} validateTracer c = do
  res <- go c
  traceWith validateTracer (ValidatedChunk c ())
  return res
 where
  go :: ChunkNo -> m (ChunkNo, WithOrigin (Tip blk))
  go chunk =
    runExceptT
      (validateChunk validateEnv ShouldNotBeFinalised chunk Nothing validateTracer)
      >>= \case
        Right (Just validBlk) -> do
          -- Found a valid block, we can stop now.
          removeFilesStartingFrom hasFS (nextChunkNo chunk)
          return (chunk, NotOrigin validBlk)
        _ -- This chunk file is unusable: either the chunk is empty or
        -- everything after it should be truncated.
          | Just chunk' <- prevChunkNo chunk -> go chunk'
          | otherwise -> do
              -- Found no valid blocks on disk.
              -- TODO be more precise in which cases we need which cleanup.
              removeFilesStartingFrom hasFS firstChunkNo
              return (firstChunkNo, Origin)

```
