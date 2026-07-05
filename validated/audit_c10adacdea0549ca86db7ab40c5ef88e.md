### Title
KES Period Pre-Start Default `t=0` in `verifyHeaderIntegrity` Bypasses KES Signature Period Validity Check — (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Praos.hs`, `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/TPraos.hs`)

---

### Summary

`verifyHeaderIntegrity` for both `Praos` and `TPraos` silently substitutes `t = 0` when the block's current KES period is **before** the certificate's start period (`currentKesPeriod < startOfKesPeriod`), then proceeds to call `verifySignedKES` with that default. This is the direct structural analog of the reported `getCurrentPeriod()` bug: a "before-start" condition returns a default value (0) instead of signalling invalidity, allowing a header whose slot predates its own operational certificate's valid range to pass the integrity check.

---

### Finding Description

In `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Praos.hs` (lines 129–146):

```haskell
verifyHeaderIntegrity slotsPerKESPeriod header =
  isRight $ KES.verifySignedKES () ocertVkHot t headerBody headerSig
 where
  ...
  currentKesPeriod =
    fromIntegral $
      unSlotNo (hbSlotNo headerBody) `div` slotsPerKESPeriod

  t
    | currentKesPeriod >= startOfKesPeriod =
        currentKesPeriod - startOfKesPeriod
    | otherwise =
        0          -- ← silent default; no rejection
```

The identical pattern appears in `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/TPraos.hs` (lines 75–92):

```haskell
  t
    | currentKesPeriod >= startOfKesPeriod =
        currentKesPeriod - startOfKesPeriod
    | otherwise =
        0          -- ← silent default; no rejection
```

When `currentKesPeriod < startOfKesPeriod` the function does **not** return `False`; it calls `verifySignedKES` at evolution `t = 0`. If the KES hot key was signed at evolution 0 (which is always the case for a freshly-issued operational certificate), the cryptographic check passes and `verifyHeaderIntegrity` returns `True` for a header whose slot is entirely outside the certificate's valid KES period range.

By contrast, the full consensus validation path in `doValidateKESSignature` (`ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs`, lines 626–638) guards the same `t = 0` fallback with an explicit prior rejection:

```haskell
c0 <= kp ?! KESBeforeStartOCERT c0 kp          -- hard rejection first
...
let t = if kp_ >= c0_ then kp_ - c0_ else 0    -- underflow guard, never reached for invalid input
```

`verifyHeaderIntegrity` has no such prior guard.

---

### Impact Explanation

`verifyHeaderIntegrity` is the implementation of the `ProtocolHeaderSupportsKES` class method documented as *"Verify that the signature on a header is correct and valid."* It is called by `verifyBlockIntegrity` (`ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Integrity.hs`, lines 15–22), which is the integrity gate used by the ChainDB/VolatileDB/ImmutableDB storage layer when reading blocks back from disk.

A crafted Shelley/Babbage/Conway block header where:
- `hbSlotNo` maps to a KES period **before** `ocertKESPeriod` (the certificate's start), and
- the KES signature is valid at evolution 0 (trivially true for any freshly-issued hot key)

will cause `verifyHeaderIntegrity` → `verifyBlockIntegrity` to return `True`, incorrectly classifying the block as uncorrupted and structurally valid. The storage layer will retain and re-serve the block. When the node subsequently attempts to apply it, `doValidateKESSignature` will reject it with `KESBeforeStartOCERT`, but the block remains in the VolatileDB as apparently "valid," creating a persistent inconsistency between the storage-layer integrity view and the consensus-layer validity view.

This is a bypass of KES certificate/signature validation in the storage integrity path, matching the "bypass of KES/certificate validation" impact class.

---

### Likelihood Explanation

Any pool operator who has ever issued an operational certificate (which is every registered stake pool) possesses a KES hot key at evolution 0. Crafting a header with a slot number that falls before `c0 * slotsPerKESPeriod` while signing it with the evolution-0 key is straightforward. The crafted block can be injected into a node's VolatileDB in a local-reproduction or private-testnet scenario (the stated in-scope entry path). On a live node the normal network path rejects the block before storage, but the storage-layer inconsistency is reachable via DB/snapshot input as explicitly listed in the scope.

---

### Recommendation

Add an explicit pre-start guard in `verifyHeaderIntegrity` for both `Praos` and `TPraos`, mirroring the guard already present in `doValidateKESSignature`:

```haskell
t
  | currentKesPeriod < startOfKesPeriod = -- reject, not default
      -- return False immediately; do not call verifySignedKES
  | otherwise =
      currentKesPeriod - startOfKesPeriod
```

Alternatively, restructure the function to return `False` directly when `currentKesPeriod < startOfKesPeriod`, before invoking `verifySignedKES`.

---

### Proof of Concept

1. Obtain any valid operational certificate `OCert { ocertKESPeriod = KESPeriod c0, ocertVkHot = vkHot }` with `c0 > 0`.
2. Craft a `HeaderBody` with `hbSlotNo = SlotNo s` where `s `div` slotsPerKESPeriod < c0` (slot is before the certificate's start period).
3. Sign `headerBody` with the KES hot key at evolution 0 to produce `headerSig`.
4. Call `verifyHeaderIntegrity slotsPerKESPeriod (Header headerBody headerSig)`.
5. Observe: `currentKesPeriod < startOfKesPeriod`, so `t = 0`; `verifySignedKES () vkHot 0 headerBody headerSig` succeeds (evolution-0 signature is valid); function returns `True`.
6. Call `doValidateKESSignature` on the same header: `c0 <= kp` fails → `KESBeforeStartOCERT` error returned.
7. The two layers disagree: storage says "valid," consensus says "invalid."