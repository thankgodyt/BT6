### Title
Envelope Validation Result Silently Discarded in `revalidateHeader` via No-Op `assertWithMsg` in Production Builds - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs`)

### Summary
`revalidateHeader` wraps its envelope check in `assertWithMsg`, which is compiled to a complete no-op in production builds (i.e., without `ENABLE_ASSERTIONS`). The `Either String ()` result of `envelopeCheck` is silently discarded, meaning the envelope validation — block number, slot number, and hash-chain continuity — is never enforced on the fast-revalidation path in production. This is the direct analog of the external report's pattern: a function returns a failure value that the caller ignores.

### Finding Description
`assertWithMsg` is defined in `Ouroboros.Consensus.Util.Assert`:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

Without the `ENABLE_ASSERTIONS` compile flag, the function unconditionally returns its second argument, making the first argument (the validation result) dead code.

`revalidateHeader` uses this function to guard its envelope check:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  chainDepState' =
    reupdateChainDepState          -- skips expensive KES/VRF checks by design
      (configConsensus cfg)
      (validateView (configBlock cfg) hdr)
      (blockSlot hdr)
      (tickedHeaderStateChainDep st)

  envelopeCheck :: Either String ()
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
```

In production, `assertWithMsg envelopeCheck result` reduces to `result` regardless of whether `envelopeCheck` is `Left err` or `Right ()`. The envelope check — which enforces consecutive block numbers, monotonically increasing slot numbers, and hash-chain continuity — is completely bypassed.

Additionally, `reupdateChainDepState` (used instead of `updateChainDepState`) skips the expensive cryptographic checks (KES/VRF signature verification) by design. The combination means that on the `revalidateHeader` path in production, **neither** the structural envelope checks nor the cryptographic protocol checks are enforced.

### Impact Explanation
If `revalidateHeader` is invoked with a header that has not been previously validated against the same `HeaderState` — whether due to a storage-layer bug, a rollback/replay inconsistency, or a crafted on-disk input — the node will construct and return a `HeaderState` that treats the invalid header as accepted. This can cause the node to build on a chain with broken block-number sequences, non-monotonic slots, or broken hash linkage, constituting an invalid-header acceptance and a potential chain-selection divergence from honest peers.

### Likelihood Explanation
`revalidateHeader` is documented as a fast path for headers "validated before w.r.t. the same exact `HeaderState`." Under normal operation the invariant holds. However, the invariant is enforced only by convention and the debug-only `assertWithMsg` guard — there is no type-level or runtime enforcement in production. Any code path that calls `revalidateHeader` with a header that was stored without a prior `validateHeader` call (e.g., after a VolatileDB replay, snapshot restore, or a future refactor) silently bypasses all header checks. The likelihood is low in the current codebase but non-zero and grows with codebase evolution.

### Recommendation
Replace the `assertWithMsg` guard with a proper `Except`-based check that is enforced unconditionally in production, or restructure `revalidateHeader` so that the envelope check is always run (even if the expensive cryptographic checks are skipped). At minimum, document clearly that `revalidateHeader` must only be called after a successful `validateHeader` against the identical `HeaderState`, and add a type-level or runtime invariant that enforces this contract independently of the `ENABLE_ASSERTIONS` flag.

### Proof of Concept

1. `assertWithMsg` is a no-op in production: [1](#0-0) 

2. `revalidateHeader` wraps `envelopeCheck` in `assertWithMsg`, so the `Either String ()` result is discarded in production: [2](#0-1) 

3. `reupdateChainDepState` (the fast path) also skips expensive KES/VRF checks, so neither structural nor cryptographic validation is enforced on this path in production: [3](#0-2) 

4. For contrast, `validateHeader` (the safe path) uses `withExcept` inside `Except`, so failures are propagated and enforced: [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L508-522)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L539-562)
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
