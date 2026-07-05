### Title
`assertWithMsg` is a compile-time no-op in production, silently discarding the envelope check in `revalidateHeader` — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs`)

---

### Summary

`assertWithMsg` in `Assert.hs` is guarded by a CPP flag (`ENABLE_ASSERTIONS`) that is absent in production builds. As a result, the envelope-validity check inside `revalidateHeader` — which verifies block number, slot, previous hash, and checkpoint — is computed but its result is **silently discarded** at runtime. This is the direct structural analog of the ERC20 `invokeTransfer` bug: a return value that signals failure is ignored, allowing the operation to proceed as if it succeeded.

---

### Finding Description

`assertWithMsg` is defined as:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
``` [1](#0-0) 

Without `ENABLE_ASSERTIONS`, the only compiled branch is `assertWithMsg _ a = a` — the function unconditionally returns its second argument, ignoring the `Either String ()` entirely.

`revalidateHeader` relies on this function to enforce the envelope check:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
``` [2](#0-1) 

In production, `envelopeCheck` is evaluated (running `validateEnvelope`, which checks block number, slot number, previous hash, and checkpoint) but its `Left`/`Right` result is **never inspected**. The function always returns the constructed `HeaderState` regardless of whether the envelope check passed or failed.

Additionally, `reupdateChainDepState` — which is called unconditionally — explicitly skips all expensive cryptographic checks (KES/VRF), as documented:

> "Re-applies a previously validated header, skipping cryptographic checks." [3](#0-2) 

`revalidateHeader` is called from `reapplyBlockLedgerResult` in `ExtLedgerState`:

```haskell
hdr =
  revalidateHeader
    (getExtLedgerCfg cfg)
    ledgerView
    (getHeader blk)
    tickedHeaderState
``` [4](#0-3) 

This path is exercised in two production scenarios:
1. **Node initialization** — replaying blocks from the ImmutableDB to reconstruct the in-memory ledger state.
2. **Chain selection** — re-applying blocks from the VolatileDB when switching between forks.

In both cases, the `tickedHeaderState` passed to `revalidateHeader` may differ from the one used during original validation (e.g., a different fork tip). If the envelope check would fail under the new state, the failure is silently swallowed.

---

### Impact Explanation

Because `assertWithMsg` is a no-op in production, `revalidateHeader` **never enforces** the envelope check. A block whose previous hash, block number, slot number, or checkpoint does not match the current `HeaderState` will be accepted without error. The resulting `HeaderState` — with an incorrect tip and/or chain-dep state — is then durably committed to the `ExtLedgerState` and used for subsequent chain selection and ledger operations.

This maps to the allowed impact: **ChainDB/LedgerDB replay/rollback bug that causes durable use of the wrong ledger state without operator fault.**

---

### Likelihood Explanation

The `revalidateHeader` path is triggered for blocks already in `prevApplied` (the set of previously-applied block points). During fork switching in chain selection, blocks from the VolatileDB are re-applied against a new fork's `tickedHeaderState`. If the chain selection logic constructs a candidate that does not perfectly fit (e.g., due to an edge case in rollback depth, EBB handling, or a future bug), the envelope check would catch it — but in production it is silently discarded. An unprivileged peer that can influence which blocks enter the VolatileDB and trigger chain selection can reach this code path. The ImmutableDB replay path is additionally reachable via crafted on-disk snapshot input.

---

### Recommendation

Replace the `assertWithMsg` guard in `revalidateHeader` with a proper runtime check that is enforced unconditionally in production. The function signature should be changed to return `Either (HeaderEnvelopeError blk) (HeaderState blk)` (matching `validateHeader`), or at minimum the envelope check should `error` unconditionally on `Left` rather than behind a CPP flag. The CPP-conditional `assertWithMsg` pattern is appropriate only for invariants that are guaranteed by construction; an envelope check against a potentially different `HeaderState` does not meet that bar.

---

### Proof of Concept

**Step 1.** Confirm `assertWithMsg` is a no-op without `ENABLE_ASSERTIONS`:

```haskell
-- Assert.hs (lines 9-13)
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg   -- only compiled with flag
#endif
assertWithMsg _ a = a                    -- always compiled; always wins in production
``` [1](#0-0) 

**Step 2.** Observe that `revalidateHeader` (lines 539–561) computes `envelopeCheck` via `validateEnvelope` but passes it only to `assertWithMsg`: [2](#0-1) 

**Step 3.** In production, the effective code is:

```haskell
revalidateHeader cfg _ledgerView hdr st =
  HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
  -- envelope check result is computed but never observed
```

**Step 4.** `reapplyBlockLedgerResult` calls `revalidateHeader` during fork-switch chain selection: [5](#0-4) 

A block received from a peer that passes `validateHeader` on fork A, is stored in the VolatileDB, and is later re-applied on fork B (where its `prevHash` no longer matches) will silently produce an incorrect `HeaderState` — the envelope error is computed but discarded.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/Abstract.hs (L184-201)
```haskell
  -- | Re-apply a header to the same 'ChainDepState' we have been able to
  -- successfully apply to before.
  --
  -- Since a header can only be applied to a single, specific,
  -- 'ChainDepState', if we apply a previously applied header again it will be
  -- applied in the very same 'ChainDepState', and therefore can't possibly
  -- fail.
  --
  -- It is worth noting that since we already know that the header is valid
  -- w.r.t. the provided 'ChainDepState', no validation checks should be
  -- performed.
  reupdateChainDepState ::
    HasCallStack =>
    ConsensusConfig p ->
    ValidateView p ->
    SlotNo ->
    Ticked (ChainDepState p) ->
    ChainDepState p
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
