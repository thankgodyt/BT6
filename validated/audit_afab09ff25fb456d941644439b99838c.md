### Title
Permanently Disabled PBFT State Invariant Allows Signing-Threshold Bypass via Crafted Snapshot — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs`)

---

### Summary

The PBFT chain-dependent state (`PBftState`) maintains a sliding window of the last `n` block signatures and a cached per-key count map. A runtime invariant check exists to verify both the window size and count-map consistency, but it is permanently disabled via `enableInvariant = False`. The `fromList`/`decodePBftState` deserialization path explicitly relies on this check as its only safety net, yet the check is never executed. A crafted on-disk snapshot with an undersized `inWindow` sequence causes `pbftWindowExceedsThreshold` to evaluate against a count map that reflects fewer blocks than the protocol window requires, bypassing the PBFT signing-threshold check and enabling unauthorized block acceptance.

---

### Finding Description

**Root cause — permanently disabled invariant:**

`enableInvariant` is a plain `Bool` constant hardcoded to `False`:

```haskell
-- TODO: Make this a CPP flag, see #1248.
enableInvariant :: Bool
enableInvariant = False

assertInvariant n st
  | enableInvariant = case invariant n st of ...
  | otherwise       = st          -- always taken in production
```

`assertInvariant` is the only call site that enforces the two structural invariants of `PBftState`:
1. `size inWindow <= n` — window does not exceed the configured size.
2. `computeCounts inWindow == counts` — cached count map is consistent with the window.

Because `enableInvariant = False`, `assertInvariant` is a no-op in every build.

**Deserialization path that accepts an invalid state:**

`decodePBftState` reconstructs the state via `uninvert` → `fromList`. The `fromList` comment explicitly acknowledges the missing check and defers to `assertInvariant`:

```haskell
-- Note: we are not checking the invariants because we don't want to require
-- the 'WindowSize' to be in the context, see #2383. When assertions are
-- enabled, we would notice the invariant violation as soon as we 'append'.
fromList :: PBftCrypto c => [PBftSigner c] -> PBftState c
fromList signers =
  PBftState { inWindow = inWindow, counts = computeCounts inWindow }
 where inWindow = Seq.fromList signers
```

`fromList` places **all** supplied signers into `inWindow` without any size bound. `computeCounts` then recomputes `counts` faithfully from that (potentially undersized) window. No window-size check is performed anywhere in the decode path.

**Threshold check reads from the corrupted count map:**

`updateChainDepState` calls `pbftWindowExceedsThreshold` after `append`:

```haskell
let state' = append cfg params (slot, gk) state
case pbftWindowExceedsThreshold params state' gk of
  Left n  -> throwError $ PBftExceededSignThreshold gk n
  Right () -> return $! state'
```

`pbftWindowExceedsThreshold` reads `countSignedBy st gk`, which returns `Map.findWithDefault 0 gk counts`. If `counts` was built from an undersized `inWindow`, the count for a key is lower than its true count over the last `n` blocks, and the threshold check passes when it should fail.

**Compounding bug in `append` trim condition:**

```haskell
(trimmedWindow, trimmedCounts) = case appendedWindow of
  x :<| xs
    | size inWindow == getWindowSize n ->   -- strict equality, not >=
        (xs, decrementKey ...)
  _otherwise -> (appendedWindow, appendedCounts)
```

The trim fires only when `size inWindow == n`. If the loaded snapshot has `size inWindow < n` (undersized), no trimming ever occurs until the window naturally grows back to `n`. During this growth phase, the per-key counts reflect only the entries present in the undersized window, not the full protocol window. Since `enableInvariant = False`, this divergence is never detected.

**Disk serialization entry point:**

The `DecodeDisk` instance for `ByronBlock` routes directly to `decodePBftState`:

```haskell
instance DecodeDisk ByronBlock (PBftState PBftByronCrypto) where
  decodeDisk _ = decodeByronChainDepState
```

The `ChainDepState` is stored as part of the `ExtLedgerState` snapshot written to disk by `encodeDiskExtLedgerState` / read back by `decodeDiskExtLedgerState`. Replacing the snapshot file with a crafted CBOR blob is the attacker-controlled entry path.

---

### Impact Explanation

**Impact: High — PBFT leader-eligibility / signing-threshold bypass.**

A genesis key that has legitimately exhausted its signing quota within the last `n` slots will appear to have signed fewer blocks than it actually has, because the count map is built from a truncated window. `pbftWindowExceedsThreshold` returns `Right ()` (allowed) instead of `Left n` (blocked). The key's delegate can then produce additional blocks beyond the protocol-mandated threshold, violating the PBFT safety property that no single genesis key may dominate more than a configured fraction of the signing window. This constitutes unauthorized block acceptance and a bypass of the PBFT certificate/signing check.

---

### Likelihood Explanation

**Likelihood: Medium.**

The entry path requires write access to the node's on-disk snapshot directory (a crafted `PBftState` CBOR blob). This is explicitly listed as an in-scope entry path ("DB/snapshot input in a local reproduction"). The Byron era is still part of the Cardano chain history and nodes must replay it; any node that loads a tampered snapshot during startup is affected. The CBOR format for `PBftState` is straightforward (a versioned map from key hash to slot list), making it trivial to craft a valid-looking but undersized snapshot. No cryptographic material is required.

---

### Recommendation

1. **Enable the invariant unconditionally** (or at minimum as a compile-time CPP flag that defaults to `True`):
   ```haskell
   enableInvariant :: Bool
   enableInvariant = True
   ```
2. **Add a window-size check in `decodePBftState`**: after `uninvert`, verify `size inWindow <= n` and reject the snapshot with a `DecoderError` if violated. This requires threading `WindowSize` into the decoder, which the existing comment (issue #2383) already acknowledges as the correct fix.
3. **Fix the trim condition in `append`** to use `>=` instead of `==`:
   ```haskell
   | size inWindow >= getWindowSize n ->
   ```
   This ensures that even if an oversized or undersized state is somehow loaded, subsequent `append` calls self-correct rather than diverging further.

---

### Proof of Concept

**Setup:** Byron private testnet with `k = 10` (window size = 10), 5 genesis keys, threshold = 0.2 (each key may sign at most 2 of any 10 consecutive blocks).

**Steps:**

1. Run the node until genesis key `GK1` has signed 2 blocks in the current window (threshold reached). The node correctly blocks further signing by `GK1`.

2. Locate the LedgerDB snapshot on disk (e.g., `<db-path>/ledger/<slot>/`). Decode the CBOR `ExtLedgerState`, extract the `PBftState` field.

3. Craft a replacement `PBftState` CBOR blob using `encodePBftState` with an `inWindow` containing only the **last 3 entries** (instead of 10), none of which are signed by `GK1`. The resulting `counts` map will show `GK1 → 0`.

4. Replace the snapshot file with the crafted blob and restart the node.

5. On restart, `decodePBftState` → `uninvert` → `fromList` loads the undersized window without error. `enableInvariant = False` suppresses the invariant check.

6. `GK1`'s delegate submits a new block. `updateChainDepState` calls `append` (no trim, window is undersized), then `pbftWindowExceedsThreshold` reads `countSignedBy st GK1 = 0 ≤ 2 = threshold` → `Right ()`. The block is accepted.

7. `GK1` can now sign additional blocks beyond its quota, violating the PBFT threshold invariant with no detection. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L125-143)
```haskell
-- | The 'PBftState' tests don't rely on this flag but check the
-- invariant manually. This flag is here so that the invariant checks could be
-- enabled while running other consensus tests, just as a sanity check.
--
-- TODO: Make this a CPP flag, see #1248.
enableInvariant :: Bool
enableInvariant = False

assertInvariant ::
  (HasCallStack, PBftCrypto c) =>
  WindowSize ->
  PBftState c ->
  PBftState c
assertInvariant n st
  | enableInvariant =
      case invariant n st of
        Right () -> st
        Left err -> error $ "Invariant violation: " ++ err
  | otherwise = st
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L220-236)
```haskell
append n signer@(PBftSigner _ gk) PBftState{..} =
  assertInvariant n $
    PBftState
      { inWindow = trimmedWindow
      , counts = trimmedCounts
      }
 where
  -- First append the signature to the right,
  (appendedWindow, appendedCounts) =
    (inWindow |> signer, incrementKey gk counts)
  -- then trim the oldest from the left, if needed.
  (trimmedWindow, trimmedCounts) = case appendedWindow of
    x :<| xs
      | size inWindow == getWindowSize n ->
          (xs, decrementKey (pbftSignerGenesisKey x) appendedCounts)
    _otherwise ->
      (appendedWindow, appendedCounts)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L264-276)
```haskell
-- | Note: we are not checking the invariants because we don't want to require
-- the 'WindowSize' to be in the context, see #2383. When assertions are
-- enabled, we would notice the invariant violation as soon as we 'append'.
--
-- PRECONDITION: the slots of the signers are in ascending order.
fromList :: PBftCrypto c => [PBftSigner c] -> PBftState c
fromList signers =
  PBftState
    { inWindow = inWindow
    , counts = computeCounts inWindow
    }
 where
  inWindow = Seq.fromList signers
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L307-317)
```haskell
decodePBftState ::
  forall c.
  PBftCrypto c =>
  forall s.
  Decoder s (PBftState c)
decodePBftState =
  decodeVersion
    [(serializationFormatVersion1, Decode decodePBftState1)]
 where
  decodePBftState1 :: forall s. Decoder s (PBftState c)
  decodePBftState1 = uninvert <$> decode
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT.hs (L359-363)
```haskell
            Just gk -> do
              let state' = append cfg params (slot, gk) state
              case pbftWindowExceedsThreshold params state' gk of
                Left n -> throwError $ PBftExceededSignThreshold gk n
                Right () -> return $! state'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT.hs (L424-435)
```haskell
pbftWindowExceedsThreshold ::
  PBftCrypto c =>
  PBftWindowParams ->
  PBftState c ->
  PBftVerKeyHash c ->
  Either Word64 ()
pbftWindowExceedsThreshold PBftWindowParams{..} st gk =
  if numSigned > threshold
    then Left numSigned
    else Right ()
 where
  numSigned = S.countSignedBy st gk
```

**File:** ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Node/Serialisation.hs (L61-67)
```haskell
-- | @'ChainDepState' ('BlockProtocol' 'ByronBlock')@
instance EncodeDisk ByronBlock (PBftState PBftByronCrypto) where
  encodeDisk _ = encodeByronChainDepState

-- | @'ChainDepState' ('BlockProtocol' 'ByronBlock')@
instance DecodeDisk ByronBlock (PBftState PBftByronCrypto) where
  decodeDisk _ = decodeByronChainDepState
```
