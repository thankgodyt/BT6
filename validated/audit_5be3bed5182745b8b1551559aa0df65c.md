### Title
Missing Discriminator Tag in `BlockOrEBB` Secondary Index Serialization Enables Type Confusion via Crafted Primary Index — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Secondary.hs`)

---

### Summary

The ImmutableDB secondary index serializes the `BlockOrEBB` field — which distinguishes a regular block (`Block SlotNo`) from an epoch boundary block (`EBB EpochNo`) — as a raw `Word64` with **no discriminator tag**. The `IsEBB` flag required to decode it correctly is derived entirely from the **primary index file** at read time. A crafted primary index file can flip this flag, causing a regular block's `SlotNo` to be silently reinterpreted as an `EpochNo` (or vice versa). Because `ValidateMostRecentChunk` (the default validation policy) skips re-validation of all but the most recent chunk, the corruption persists durably and is never detected.

---

### Finding Description

**The tag-less serialization design**

`BlockOrEBB` is defined in `Types.hs`:

```haskell
data BlockOrEBB
  = Block !SlotNo
  | EBB   !EpochNo
``` [1](#0-0) 

Both `SlotNo` and `EpochNo` are newtypes over `Word64`. The serializer in `Secondary.hs` writes only the raw 64-bit integer — the constructor tag is **omitted**:

```haskell
getBlockOrEBB :: IsEBB -> Get BlockOrEBB
getBlockOrEBB IsEBB    = EBB   . EpochNo <$> Get.getWord64be
getBlockOrEBB IsNotEBB = Block . SlotNo  <$> Get.getWord64be

putBlockOrEBB :: BlockOrEBB -> Put
putBlockOrEBB blockOrEBB = Put.putWord64be $ case blockOrEBB of
  Block slotNo  -> unSlotNo  slotNo
  EBB   epochNo -> unEpochNo epochNo
``` [2](#0-1) 

The design is explicitly acknowledged as a known weakness in the technical report: *"We omit the tag distinguishing between the two constructors in the serialisation because in nearly all cases, this information has already been retrieved from the primary index … In hindsight, having the tag in the serialisation would have simplified the implementation."*

**How `IsEBB` is derived from the primary index**

`readPrimaryIndex` in `Cache.hs` determines `firstIsEBB` solely by inspecting whether the first relative slot in the primary index is filled and is an EBB slot:

```haskell
readPrimaryIndex pb hasFS chunkInfo chunk = do
  primaryIndex <- Primary.load pb hasFS chunk
  let firstIsEBB
        | Primary.containsSlot primaryIndex firstRelativeSlot
        , Primary.isFilledSlot primaryIndex firstRelativeSlot =
            relativeSlotIsEBB firstRelativeSlot
        | otherwise = IsNotEBB
  return (primaryIndex, firstIsEBB)
``` [3](#0-2) 

This `firstIsEBB` is then passed directly to `readSecondaryIndex` → `Secondary.readAllEntries`, which uses it to decode the first entry: [4](#0-3) 

Inside `readAllEntries`, after the first entry, `IsNotEBB` is hardcoded for all subsequent entries:

```haskell
-- Pass 'IsNotEBB' because there can only be one EBB and that must
-- be the first one in the file.
go IsNotEBB remaining acc' (Just entry)
``` [5](#0-4) 

**The collision: two types, one shared 8-byte field, no tag**

This is the direct analog to the external report's `params`/`pools` collision. The secondary index's `block_or_ebb` field (8 bytes, `u8` in the KAITAI spec) is shared between two semantically incompatible types: [6](#0-5) 

If the primary index for chunk `C` is crafted to mark slot 0 as filled (making `relativeSlotIsEBB` return `IsEBB`), but the secondary index's first entry actually belongs to a regular block, then `getBlockOrEBB IsEBB` decodes the stored `SlotNo` value as an `EpochNo`. For example, a regular block at slot 21600 would be decoded as `EBB (EpochNo 21600)` — a nonsensical epoch number — instead of `Block (SlotNo 21600)`.

**Validation gap**

`ValidateMostRecentChunk` (the default policy used in production) only validates the most recent chunk: [7](#0-6) 

Crafted primary index files for any chunk other than the most recent are never re-validated against the chunk file. The `reconstructPrimaryIndex` path in `Validation.hs` that would catch the mismatch is only exercised under `ValidateAllChunks`. [8](#0-7) 

---

### Impact Explanation

**High — ImmutableDB corruption/replay bug causing durable use of wrong ledger state or permanent acceptance/rejection of a valid chain.**

When `blockOrEBB` is decoded with the wrong constructor:

1. `isBlockOrEBB` returns `IsEBB` for a regular block, causing the iterator and chain-selection logic to treat it as an EBB. EBBs and regular blocks are processed by different decoders (`CtxtByronBoundary` vs `CtxtByronRegular`). Feeding a regular block's bytes to the EBB decoder causes a decoding failure or silently wrong header data.

2. The iterator's `iteratorHasNext` logic compares the decoded slot/epoch number against the requested end-point. A `SlotNo` reinterpreted as an `EpochNo` produces a wildly different numeric value, causing the iterator to terminate prematurely (skipping valid blocks) or overshoot (returning extra blocks).

3. Because the ImmutableDB is the authoritative, append-only store for finalized chain history, any corruption here is **durable**: the node will permanently serve wrong block metadata to chain-sync peers and make wrong chain-selection decisions based on it, without any operator-visible error.

---

### Likelihood Explanation

**Medium.** The attack requires the ability to supply a crafted on-disk DB or snapshot to a node — explicitly within the stated scope ("DB/snapshot input in a local reproduction"). Concretely:

- A node operator who bootstraps from an untrusted snapshot (e.g., downloaded from a third-party source) loads crafted primary index files.
- The node opens with `ValidateMostRecentChunk` (the default), so all but the most recent chunk's primary index is accepted without cross-checking against the chunk file.
- No network-level privilege is required; no key material is needed.

---

### Recommendation

**Short term:** Add the constructor tag back to the `BlockOrEBB` on-disk serialization. Replace the tag-less `putBlockOrEBB`/`getBlockOrEBB` pair with a tagged encoding (e.g., a leading `Word8`: `0` for `Block`, `1` for `EBB`) so the secondary index is self-describing and does not depend on the primary index for correct decoding. This is a format migration but is isolated to the secondary index files.

**Long term:** Cross-validate the `IsEBB` flag derived from the primary index against the `blockOrEBB` field decoded from the secondary index during `validateAndReopen`, regardless of `ValidationPolicy`. Any mismatch should be treated as `InvalidFileError` and trigger chunk reconstruction from the raw chunk file.

---

### Proof of Concept

1. Identify any finalized chunk `C` in the ImmutableDB whose first entry is a regular block (not an EBB) — this is true for all Shelley-era and later chunks.
2. Open the corresponding primary index file `C.primary`. The file starts with a 1-byte version number followed by `Word32` secondary offsets. Overwrite the first offset entry so that `isFilledSlot` returns `True` for relative slot 0 (the EBB slot position), e.g., by writing a non-zero value at offset `sizeof(versionByte) = 1`.
3. Start the node with `ValidateMostRecentChunk` (default). The crafted chunk `C` is not re-validated.
4. Trigger an iterator over chunk `C` (e.g., via a chain-sync client requesting blocks in that range). `readPrimaryIndex` reads the crafted file, computes `firstIsEBB = IsEBB`, and passes it to `readSecondaryIndex`.
5. `Secondary.readAllEntries` decodes the first entry with `getEntry IsEBB`, interpreting the stored `SlotNo` as an `EpochNo`. The resulting `Entry` has `blockOrEBB = EBB (EpochNo <slot_value>)`.
6. The iterator returns this entry with `isBlockOrEBB = IsEBB`. Downstream code selects the EBB decoder path for a regular block, producing a decoding error or silently wrong header, permanently corrupting the node's view of that portion of chain history.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Types.hs (L38-45)
```haskell
data BlockOrEBB
  = Block !SlotNo
  | EBB !EpochNo
  deriving (Eq, Show, Generic, NoThunks)

isBlockOrEBB :: BlockOrEBB -> IsEBB
isBlockOrEBB (Block _) = IsNotEBB
isBlockOrEBB (EBB _) = IsEBB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Types.hs (L66-85)
```haskell
data ValidationPolicy
  = -- | The chunk and index files of the most recent chunk stored on disk will
    -- be validated.
    --
    -- Prior chunk and index files are ignored, even their presence will not
    -- be checked.
    --
    -- A 'MissingFileError' or an 'InvalidFileError' will be thrown in case of a
    -- missing or invalid chunk file, or an invalid index file.
    --
    -- Because not all files are validated, subsequent operations on the
    -- database after opening may result in unexpected errors.
    ValidateMostRecentChunk
  | -- | The chunk and index files of all chunks starting from the first one up
    -- to the last chunk stored on disk will be validated.
    --
    -- A 'MissingFileError' or an 'InvalidFileError' will be thrown in case of a
    -- missing or invalid chunk file, or an invalid index file.
    ValidateAllChunks
  deriving (Show, Eq, Generic)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Secondary.hs (L84-91)
```haskell
getBlockOrEBB :: IsEBB -> Get BlockOrEBB
getBlockOrEBB IsEBB = EBB . EpochNo <$> Get.getWord64be
getBlockOrEBB IsNotEBB = Block . SlotNo <$> Get.getWord64be

putBlockOrEBB :: BlockOrEBB -> Put
putBlockOrEBB blockOrEBB = Put.putWord64be $ case blockOrEBB of
  Block slotNo -> unSlotNo slotNo
  EBB epochNo -> unEpochNo epochNo
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Secondary.hs (L302-304)
```haskell
            -- Pass 'IsNotEBB' because there can only be one EBB and that must
            -- be the first one in the file.
            go IsNotEBB remaining acc' (Just entry)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Cache.hs (L511-530)
```haskell
readPrimaryIndex ::
  (HasCallStack, IOLike m, Typeable blk, StandardHash blk) =>
  Proxy blk ->
  HasFS m h ->
  ChunkInfo ->
  ChunkNo ->
  -- | The primary index and whether it starts with an EBB or not
  m (PrimaryIndex, IsEBB)
readPrimaryIndex pb hasFS chunkInfo chunk = do
  primaryIndex <- Primary.load pb hasFS chunk
  let firstIsEBB
        | Primary.containsSlot primaryIndex firstRelativeSlot
        , Primary.isFilledSlot primaryIndex firstRelativeSlot =
            relativeSlotIsEBB firstRelativeSlot
        | otherwise =
            IsNotEBB
  return (primaryIndex, firstIsEBB)
 where
  firstRelativeSlot :: RelativeSlot
  firstRelativeSlot = firstBlockOrEBB chunkInfo chunk
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Cache.hs (L532-557)
```haskell
readSecondaryIndex ::
  ( HasCallStack
  , ConvertRawHash blk
  , IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  HasFS m h ->
  ChunkNo ->
  IsEBB ->
  m [Entry blk]
readSecondaryIndex hasFS@HasFS{hGetSize} chunk firstIsEBB = do
  !chunkFileSize <- withFile hasFS chunkFile ReadMode hGetSize
  Secondary.readAllEntries
    hasFS
    secondaryOffset
    chunk
    stopCondition
    chunkFileSize
    firstIsEBB
 where
  chunkFile = fsPathChunkFile chunk
  -- Read from the start
  secondaryOffset = 0
  -- Don't stop until the end
  stopCondition = const False
```

**File:** ouroboros-consensus-cardano/cddl/disk/immutable/secondary.ksy (L23-24)
```text
      - id: block_or_ebb
        type: u8
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Validation.hs (L64-95)
```haskell
-- | Bundle of arguments used most validation functions.
--
-- Note that we don't use "Ouroboros.Consensus.Storage.ImmutableDB.Impl.Index"
-- because we are reading and manipulating index files in different ways, e.g.,
-- truncating them.
data ValidateEnv m blk h = ValidateEnv
  { hasFS :: !(HasFS m h)
  , chunkInfo :: !ChunkInfo
  , tracer :: !(Tracer m (TraceEvent blk))
  , cacheConfig :: !Index.CacheConfig
  , codecConfig :: !(CodecConfig blk)
  , checkIntegrity :: !(blk -> Bool)
  }

-- | Perform validation as per the 'ValidationPolicy' using 'validate' and
-- create an 'OpenState' corresponding to its outcome using 'mkOpenState'.
validateAndReopen ::
  forall m blk h.
  ( IOLike m
  , GetPrevHash blk
  , HasBinaryBlockInfo blk
  , DecodeDisk blk (Lazy.ByteString -> Either Plain.DecoderError blk)
  , ConvertRawHash blk
  , Eq h
  , HasCallStack
  ) =>
  ValidateEnv m blk h ->
  ResourceRegistry m ->
  ValidationPolicy ->
  m (OpenState m blk h)
validateAndReopen validateEnv registry valPol = wrapFsError (Proxy @blk) $ do
  (chunk, tip) <- validate validateEnv valPol
```
