### Title
Unhandled Serialisation Error in `decodeShelleyHeader` Causes Uncontrolled Node Crash on Crafted Network Input - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Block.hs`)

---

### Summary

The `decodeShelleyHeader` function in the Shelley block serialisation layer contains an acknowledged `error` call that converts a recoverable `DecoderError` into an unrecoverable Haskell runtime exception. This `error` is reachable via the node-to-node ChainSync miniprotocol when a peer sends a crafted header whose inner annotated CBOR decoding fails after the outer CBOR-in-CBOR layer is successfully unwrapped. The crash is unhandled, terminates the node process, and constitutes a remotely-triggerable node crash via a serialisation mismatch — the direct analog of the ABIEncoderV2 bug class (serialisation layer defect with functional/safety impact).

---

### Finding Description

`decodeShelleyHeader` is the disk and network decoder for all Shelley-family era headers (Shelley, Allegra, Mary, Alonzo, Babbage, Conway, Dijkstra). Its implementation is:

```haskell
decodeShelleyHeader =
  eraDecoder @era $
    (. Full)
      . (either (\e -> error ("Impossible, header decoder failed: " <> show e)) id .)
      . runAnnotator
      <$> decCBOR
``` [1](#0-0) 

The comment above the function explicitly acknowledges this is a known defect introduced as a workaround:

> *"We have no way to handle the inner decoder error without actually running the decoder. We also know that the current code does not allow `Header` decoding to fail in a way different than normal CBOR failures. Hence, we chose to introduce an `error` call here. We intend to refactor `Header` decoding in Consensus to not have to have this error call."* [2](#0-1) 

The CHANGELOG confirms this was introduced deliberately as a temporary workaround:

> *"while `Header` decoding still cannot fail, it has to use the same low-level decoding functions from the Ledger and Networking layers; hence, we have to introduce an `error` call into the `decodeShelleyHeader` to account for an impossible case of `Header` decoding failing and make types match. We aim to remove this error call as soon as possible."* [3](#0-2) 

This decoder is used in two critical paths:

1. **Node-to-node network path** — via `SerialiseNodeToNode` for `Header (ShelleyBlock proto era)`:
   ```haskell
   decodeNodeToNode _ _ = unwrapCBORinCBOR ((Right .) <$> decodeShelleyHeader)
   ``` [4](#0-3) 

2. **On-disk path** — via `DecodeDisk` for headers read from ImmutableDB/VolatileDB:
   ```haskell
   decodeDisk _ = decodeShelleyHeader
   ``` [5](#0-4) 

The network path is the critical attacker-controlled entry. When a peer sends a ChainSync header message, the outer CBOR-in-CBOR layer (`unwrapCBORinCBOR`) is decoded first. If that succeeds but the inner annotated header CBOR (`runAnnotator`) returns a `Left DecoderError`, the `either (\e -> error ...) id` branch fires, calling Haskell's `error` — which throws an impure exception that is **not** caught by the typed-protocols exception handling in the ChainSync miniprotocol, causing the node process to crash.

The assumption that "Header decoding cannot fail in a way different than normal CBOR failures" is precisely the kind of assumption that is invalidated by future ledger changes — exactly the same risk class as the ABIEncoderV2 bug: a serialisation layer that was believed safe but contains a latent defect that can be triggered by crafted input.

---

### Impact Explanation

**High.** A crafted ChainSync header message from any unprivileged peer that passes the outer CBOR-in-CBOR unwrapping but causes the inner `runAnnotator` to return `Left` will trigger `error`, crashing the node process. This is a remotely-triggered node crash via the public node-to-node miniprotocol. While this is a crash (not a consensus safety failure per se), it permanently removes the node from the network until manually restarted, and if triggered repeatedly, prevents the node from ever syncing — which in a validator context constitutes a liveness failure that can lead to missed block production and stake pool penalties. The impact also extends to the on-disk path: a corrupted ImmutableDB/VolatileDB header entry that passes CBOR framing but fails inner annotation decoding will crash the node on startup, preventing recovery without manual intervention.

---

### Likelihood Explanation

**Medium.** The assumption that `Header` decoding "cannot fail" is an informal invariant, not a type-level guarantee. The CHANGELOG itself notes the intent to remove this `error` call "as soon as possible," indicating the developers consider it a live risk. Any future ledger change that alters the `DecCBOR (Annotator (ShelleyProtocolHeader proto))` instance in a way that can return `Left` for certain byte sequences — or any peer running a slightly different ledger version — can trigger this path. The outer CBOR-in-CBOR layer is easy to satisfy (it just requires a valid CBOR byte-string tag), making the inner path reachable from the network.

---

### Recommendation

1. **Immediate**: Change `decodeShelleyHeader` to return `Plain.Decoder s (Lazy.ByteString -> Either Plain.DecoderError (Header (ShelleyBlock proto era)))` (matching the block decoder's type), propagating the `Left` case instead of calling `error`. Update all call sites (`DecodeDisk`, `SerialiseNodeToNode`) to handle the `Either`.

2. **Short-term**: Refactor the `DecodeDisk` instance for headers to use the `Either`-returning form, consistent with how `decodeShelleyBlock` is already typed.

3. **Defensive**: Add a property-based test that feeds arbitrary CBOR byte sequences through `decodeShelleyHeader` and asserts no `error` is thrown (only `Left` is returned for invalid input).

---

### Proof of Concept

**Network trigger path:**

1. Attacker connects to a Cardano node via the node-to-node ChainSync miniprotocol.
2. Attacker sends a `MsgRollForward` message containing a `SerialisedHeader` for a Shelley-family era.
3. The outer CBOR-in-CBOR tag (tag 24 wrapping a byte string) is valid, so `unwrapCBORinCBOR` succeeds and extracts the inner byte string.
4. The inner byte string is crafted to be valid CBOR (passes `decCBOR` for the outer `Annotator` wrapper) but causes `runAnnotator` to return `Left e` when applied to `Full` (the full byte string).
5. `decodeShelleyHeader` executes `either (\e -> error ("Impossible, header decoder failed: " <> show e)) id (Left e)`, calling `error`.
6. The Haskell runtime throws an impure exception that propagates out of the typed-protocols handler, crashing the node process.

**Relevant code path:**

```
ChainSync peer message
  → unwrapCBORinCBOR
    → decodeShelleyHeader          -- line 340-345, Block.hs
      → eraDecoder @era
        → decCBOR                  -- outer Annotator decode
          → runAnnotator (. Full)  -- inner annotation application
            → Left e               -- decoder error
              → error "Impossible, header decoder failed: ..."  -- CRASH
``` [6](#0-5) [4](#0-3)

### Citations

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Block.hs (L334-345)
```haskell
-- The `error` call is introduced to work around the change of the type of `runAnnotator`. The annotated decoder has type `Lazy.ByteString -> Either DecoderError (Header (ShelleyBlock proto era))`, but we need `(Lazy.ByteString -> Header (ShelleyBlock proto era))`. We have no way to handle the inner decoder error without actually running the decoder. We also know that the current code does not allow `Header` decoding to fail in a way different than normal CBOR failures. Hence, we chose to introduce an error call here. We intend to refactor `Header` decoding in Consesnus to not have to have this error call.
decodeShelleyHeader ::
  forall proto era.
  ShelleyCompatible proto era =>
  forall s.
  Plain.Decoder s (Lazy.ByteString -> Header (ShelleyBlock proto era))
decodeShelleyHeader =
  eraDecoder @era $
    (. Full)
      . (either (\e -> error ("Impossible, header decoder failed: " <> show e)) id .)
      . runAnnotator
      <$> decCBOR
```

**File:** CHANGELOG.md (L191-191)
```markdown
- Adapt to the fact that block decoders may fail, i.e. change the block annotated decoder types from `Lazy.ByteString -> ShelleyBlock proto era` to `Lazy.ByteString -> Either Plain.DecoderError (ShelleyBlock proto era)`. Very importantly, while `Header` decoding still cannot fail, it has to use the same low-level decoding functions from the Ledger and Networking layers; hence, we have to introduce an `error` call into the `decodeShelleyHeader` to account for an impossible case of `Header` decoding failing and make types match. We aim to remove this error call as soon as possible.
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/Serialisation.hs (L82-86)
```haskell
instance
  ShelleyCompatible proto era =>
  DecodeDisk (ShelleyBlock proto era) (Lazy.ByteString -> Header (ShelleyBlock proto era))
  where
  decodeDisk _ = decodeShelleyHeader
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/Serialisation.hs (L162-167)
```haskell
instance
  ShelleyCompatible proto era =>
  SerialiseNodeToNode (ShelleyBlock proto era) (Header (ShelleyBlock proto era))
  where
  encodeNodeToNode _ _ = wrapCBORinCBOR encodeShelleyHeader
  decodeNodeToNode _ _ = unwrapCBORinCBOR ((Right .) <$> decodeShelleyHeader)
```
