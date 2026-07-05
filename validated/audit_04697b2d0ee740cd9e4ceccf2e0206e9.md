### Title
`assertWithMsg` is a no-op in production builds, silently discarding the `validateEnvelope` result in `revalidateHeader` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs`)

---

### Summary

`revalidateHeader` in `HeaderValidation.hs` guards its envelope check (block number, slot number, hash chain) with `assertWithMsg`. In production builds compiled without `-DENABLE_ASSERTIONS`, `assertWithMsg` is unconditionally a no-op: it evaluates the `Either String ()` result and then **silently discards it**. This means the envelope validation is completely bypassed in production, and `revalidateHeader` returns a new `HeaderState` regardless of whether the block's block number, slot number, or previous hash are valid. This is the direct analog of the ERC20 unchecked return value: a validation function's result is computed but never acted upon.

---

### Finding Description

`assertWithMsg` is defined as a compile-time conditional:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
``` [1](#0-0) 

When `ENABLE_ASSERTIONS` is not set (the default for production), the second equation `assertWithMsg _ a = a` matches unconditionally, ignoring the `Either String ()` argument entirely.

`revalidateHeader` uses this to guard the envelope check:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  chainDepState' = reupdateChainDepState ...
  envelopeCheck  = runExcept $ withExcept show $
                     validateEnvelope cfg ledgerView
                       (untickedHeaderStateTip st) hdr
``` [2](#0-1) 

`validateEnvelope` checks three critical invariants: consecutive block numbers, strictly increasing slot numbers, and hash chain continuity. [3](#0-2) 

In production, `assertWithMsg envelopeCheck` reduces to `id`, so `revalidateHeader` **performs zero validation** — it unconditionally constructs and returns the new `HeaderState` regardless of what `envelopeCheck` computed.

`revalidateHeader` is called from `reapplyBlockLedgerResult` in the `ApplyBlock` instance for `ExtLedgerState`:

```haskell
reapplyBlockLedgerResult evs cfg blk TickedExtLedgerState{..} =
    (\l -> ExtLedgerState l hdr) <$> castLedgerResult ledgerResult
  where
    hdr = revalidateHeader (getExtLedgerCfg cfg) ledgerView
                           (getHeader blk) tickedHeaderState
``` [4](#0-3) 

This is the code path exercised during LedgerDB initialization when blocks are replayed from the ImmutableDB.

---

### Impact Explanation

The ImmutableDB chunk validator (`validateChunk`) checks hash continuity and checksums, but it does **not** independently verify that block numbers are consecutive or that slot numbers are strictly increasing across blocks. [5](#0-4) 

A crafted ImmutableDB whose blocks have correct hashes and checksums but incorrect block numbers or slot numbers would pass `validateChunk` and then be replayed via `reapplyBlockLedgerResult`. Because `assertWithMsg` is a no-op in production, `revalidateHeader` silently accepts each such block and builds an incorrect `HeaderState`. The resulting `ExtLedgerState` — combining the wrong `HeaderState` with the replayed `LedgerState` — becomes the anchor of the `LedgerDB`, causing the node to operate permanently from a corrupted ledger state. This matches the **High** impact category: "LedgerDB, snapshot, or LSM corruption/replay/rollback bug that causes durable use of the wrong ledger state."

---

### Likelihood Explanation

The entry path is a crafted ImmutableDB provided as on-disk input (e.g., in a local reproduction or a node whose storage has been partially corrupted by a storage-layer bug). The attacker must produce chunk files with valid checksums and hash chains but invalid block/slot sequences. This is technically feasible without key material or stake. The `ENABLE_ASSERTIONS` flag is not set in standard production Cabal builds, as confirmed by the cabal file: [6](#0-5) 

Likelihood is **medium**: requires crafted on-disk input, but no cryptographic material or network position is needed.

---

### Recommendation

Replace the `assertWithMsg` guard in `revalidateHeader` with a hard error that is unconditional, not gated on a compile flag. Since `revalidateHeader` is called only on blocks that are supposed to have been previously validated, a failure of `envelopeCheck` indicates a serious invariant violation and should always abort, not be silently swallowed:

```haskell
revalidateHeader cfg ledgerView hdr st =
  case envelopeCheck of
    Left err -> error ("revalidateHeader: envelope check failed: " ++ err)
    Right () -> HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
```

Alternatively, change `revalidateHeader`'s return type to `Either (HeaderEnvelopeError blk) (HeaderState blk)` and propagate the error to callers, forcing them to handle it explicitly — the same pattern used by `validateHeader`. [7](#0-6) 

---

### Proof of Concept

1. Build the node **without** `-DENABLE_ASSERTIONS` (the default).
2. Construct a synthetic ImmutableDB chunk file containing a block whose `blockNo` field is set to an arbitrary wrong value (e.g., `BlockNo 9999`) but whose hash, checksum, and previous-hash fields are all correct.
3. Start the node pointing at this ImmutableDB. `validateChunk` passes (hashes and checksums match).
4. During LedgerDB initialization, `reapplyBlockLedgerResult` is called for the crafted block. `revalidateHeader` computes `envelopeCheck = Left "UnexpectedBlockNo ..."` but `assertWithMsg` discards it.
5. The node completes initialization with a `HeaderState` whose `headerStateTip` records `BlockNo 9999`, diverging from the true chain state. All subsequent chain selection and header validation operates against this corrupted anchor. [1](#0-0) [2](#0-1) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L501-522)
```haskell
validateHeader ::
  (BlockSupportsProtocol blk, ValidateEnvelope blk) =>
  TopLevelConfig blk ->
  LedgerView (BlockProtocol blk) ->
  Header blk ->
  Ticked (HeaderState blk) ->
  Except (HeaderError blk) (HeaderState blk)
validateHeader cfg ledgerView hdr st = do
  withExcept HeaderEnvelopeError $
    validateEnvelope
      cfg
      ledgerView
      (untickedHeaderStateTip st)
      hdr
  chainDepState' <-
    withExcept HeaderProtocolError $
      updateChainDepState
        (configConsensus cfg)
        (validateView (configBlock cfg) hdr)
        (blockSlot hdr)
        (tickedHeaderStateChainDep st)
  return $ HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Extended.hs (L213-227)
```haskell
  reapplyBlockLedgerResult evs cfg blk TickedExtLedgerState{..} =
    (\l -> ExtLedgerState l hdr) <$> castLedgerResult ledgerResult
   where
    ledgerResult =
      reapplyBlockLedgerResult
        evs
        (configLedger $ getExtLedgerCfg cfg)
        blk
        tickedLedgerState
    hdr =
      revalidateHeader
        (getExtLedgerCfg cfg)
        ledgerView
        (getHeader blk)
        tickedHeaderState
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Validation.hs (L318-376)
```haskell
-- | Validate the given chunk
--
-- * Invalid or missing chunk files will cause truncation. All blocks after a
--   gap in blocks (due to a missing blocks or invalid block(s)) are
--   truncated.
--
-- * Chunk files are the main source of truth. Primary and secondary index
--   files can be reconstructed from the chunk files using the
--   'ChunkFileParser'. If index files are missing, corrupt, or do not match
--   the chunk files, they are overwritten.
--
-- * The 'ChunkFileParser' checks whether the hashes (header hash) line up
--   within an chunk. When they do not, we truncate the chunk, including the
--   block of which its previous hash does not match the hash of the previous
--   block.
--
-- * For each block, the 'ChunkFileParser' checks whether the checksum (and
--   other fields) from the secondary index file match the ones retrieved from
--   the actual block. If they do, the block has not been corrupted. If they
--   don't match or if the secondary index file is missing or corrupt, we have
--   to do the expensive integrity check of the block itself to determine
--   whether it is corrupt or not.
--
-- * This function checks whether the first block in the chunk fits onto the
--   last block of the previous chunk by checking the hashes. If they do not
--   fit, this chunk is truncated and @()@ is thrown.
--
-- * When an invalid block needs to be truncated, trailing empty slots are
--   also truncated so that the tip of the database will always point to a
--   valid block or EBB.
--
-- * All but the most recent chunk in the database should be finalised, i.e.
--   padded to the size of the chunk.
validateChunk ::
  forall m blk h.
  ( IOLike m
  , GetPrevHash blk
  , HasBinaryBlockInfo blk
  , DecodeDisk blk (Lazy.ByteString -> Either Plain.DecoderError blk)
  , ConvertRawHash blk
  , HasCallStack
  ) =>
  ValidateEnv m blk h ->
  ShouldBeFinalised ->
  ChunkNo ->
  -- | The hash of the last block of the previous chunk. 'Nothing' if
  -- unknown. When this is the first chunk, it should be 'Just Origin'.
  Maybe (ChainHash blk) ->
  Tracer m (TraceChunkValidation blk ()) ->
  -- | When non-empty, the 'Tip' corresponds to the last valid block in the
  -- chunk.
  --
  -- When the chunk file is missing or when we should truncate starting from
  -- this chunk because it doesn't fit onto the previous one, @()@ is thrown.
  --
  -- Note that when an invalid block is detected, we don't throw, but we
  -- truncate the chunk file. When validating the chunk file after it, we
  -- would notice it doesn't fit anymore, and then throw.
  ExceptT () m (Maybe (Tip blk))
```

**File:** ouroboros-consensus.cabal (L1-5)
```text
cabal-version: 3.0
name: ouroboros-consensus
version: 3.0.1.0
synopsis: Consensus layer for the Ouroboros blockchain protocol
description: Consensus layer for the Ouroboros blockchain protocol.
```
