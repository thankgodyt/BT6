### Title
`revalidateHeader` Silently Discards Envelope Validation Failures in Production Builds via `assertWithMsg` No-Op — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs`)

---

### Summary

`revalidateHeader` guards its header envelope check (block number, slot number, prev-hash) with `assertWithMsg`, which is compiled to a **complete no-op** in production builds that lack the `ENABLE_ASSERTIONS` flag. The result is that in every production node, `revalidateHeader` unconditionally returns a new `HeaderState` regardless of whether the envelope is valid. This is directly analogous to the ERC20 report's two failure modes: one code path (`validateHeader`) properly enforces the check and propagates errors; the other (`revalidateHeader`) silently ignores failures. A crafted on-disk snapshot or ImmutableDB containing headers with invalid envelopes is silently accepted during replay, causing the node to durably operate on a wrong ledger state.

---

### Finding Description

**`assertWithMsg` is a compile-time no-op in production.** [1](#0-0) 

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

Without `ENABLE_ASSERTIONS`, the `Left msg` branch is not compiled in. The function always returns its second argument, silently discarding any `Left` error.

**`revalidateHeader` relies on `assertWithMsg` for its only envelope check.** [2](#0-1) 

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
```

In a production build this is semantically identical to:

```haskell
revalidateHeader cfg ledgerView hdr st =
  HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
```

The envelope check — which verifies consecutive block numbers, monotonically increasing slot numbers, and that the previous-hash field matches the actual tip — is **never enforced**.

**`validateHeader` (the "first-time" path) properly enforces the same check.** [3](#0-2) 

```haskell
validateHeader cfg ledgerView hdr st = do
  withExcept HeaderEnvelopeError $
    validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
  chainDepState' <- withExcept HeaderProtocolError $
    updateChainDepState ...
  return $ HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
```

This returns `Except (HeaderError blk) (HeaderState blk)` and propagates any envelope failure to the caller.

**The inconsistency maps directly to the ERC20 three-type taxonomy:**

| ERC20 analogy | Consensus analogy |
|---|---|
| Type 1/2 — `require(token.transferFrom(...))` enforces the bool | `validateHeader` — `Except` enforces the envelope check |
| Type 3 — `token.transfer(...)` return value silently ignored | `revalidateHeader` — `assertWithMsg` silently ignored in production |

**`revalidateHeader` is called during ImmutableDB replay.**

`reapplyBlockLedgerResult` in `Extended.hs` calls `revalidateHeader` (confirmed by grep: 2 call sites in that file). [4](#0-3) 

During node initialisation, `replayStartingWith` drives `initReapplyBlock` over every block in the ImmutableDB: [5](#0-4) 

Every block replayed from the ImmutableDB passes through `reapplyBlockLedgerResult` → `revalidateHeader`, with the envelope check silently skipped in production.

---

### Impact Explanation

A crafted ImmutableDB or ledger snapshot containing a block whose header has an invalid envelope (wrong block number, non-monotone slot, or mismatched prev-hash) will be silently accepted during replay. The node will construct and persist a `HeaderState` — and therefore an `ExtLedgerState` — that is inconsistent with the actual chain. Downstream consequences include:

- The node's chain-dependent state (`ChainDepState`) is advanced from a corrupted base, invalidating all subsequent leader-eligibility and VRF/KES checks that depend on it.
- Chain selection operates on a ledger state that does not correspond to any valid chain, potentially causing the node to prefer or reject candidates incorrectly.
- The corrupted state is durable: it is written back to the LedgerDB and used across restarts.

This falls within the allowed scope: **High — ImmutableDB/LedgerDB replay bug that causes durable use of the wrong ledger state without operator fault** (the operator did not intentionally corrupt the DB; the node's own replay logic failed to detect the corruption).

---

### Likelihood Explanation

The triggering condition requires that the ImmutableDB or a ledger snapshot on disk contains a header with an invalid envelope. In normal operation this cannot happen because headers enter the ImmutableDB only after passing `validateHeader`. However:

- A crafted snapshot file (the explicit "DB/snapshot input in a local reproduction" entry point named in the audit scope) trivially satisfies the precondition.
- Any future bug in the code path that moves blocks from the VolatileDB to the ImmutableDB could silently introduce invalid headers that `revalidateHeader` would then accept without complaint.
- The silent nature of the failure (no log, no exception, no disconnect) means the corruption goes undetected until downstream consensus divergence is observed.

Likelihood is **low** for mainnet nodes under normal operation, but the silent-failure property makes it **high-severity** when the precondition is met, and the precondition is reachable via the named DB/snapshot input vector.

---

### Recommendation

Replace the `assertWithMsg` guard in `revalidateHeader` with an unconditional enforcement mechanism. Two options:

1. **Change the return type** to `Either (HeaderError blk) (HeaderState blk)` (matching `validateHeader`) and use `withExcept HeaderEnvelopeError $ validateEnvelope ...` directly. Callers that currently treat `revalidateHeader` as infallible would need to handle the error (e.g., with `error` at the call site if the invariant truly holds, making the failure loud rather than silent).

2. **Use `error` directly** instead of `assertWithMsg` so that envelope failures always crash the process regardless of build flags, making the invariant violation immediately visible.

The root cause — `assertWithMsg` being a silent no-op in production — should also be audited at every other call site (`assertKnownIntersectionInvariants` in `ChainSync/Client.hs`, `withTime`, etc.) for similar silent-failure exposure. [1](#0-0) 

---

### Proof of Concept

1. Construct a minimal ImmutableDB (or ledger snapshot) containing a single block whose header carries `blockNo = 5` but whose predecessor in the DB has `blockNo = 3` (skipping block 4), violating the consecutive-block-number invariant enforced by `validateEnvelope`.
2. Start a node pointing at this ImmutableDB. `replayStartingWith` iterates over the blocks and calls `initReapplyBlock` → `reapplyBlockLedgerResult` → `revalidateHeader`.
3. In a production build (no `ENABLE_ASSERTIONS`), `assertWithMsg envelopeCheck (HeaderState ...)` evaluates `envelopeCheck` to `Left "UnexpectedBlockNo 4 5"` but discards it, returning the `HeaderState` unconditionally.
4. The node completes initialisation with a `HeaderState` whose `headerStateTip` records block 5 as following block 3, a structural lie that propagates into every subsequent chain-selection and ledger-view computation.
5. In a debug build (`ENABLE_ASSERTIONS` set), the same sequence crashes with `error "UnexpectedBlockNo 4 5"`, confirming the check fires correctly only under that flag. [6](#0-5) [1](#0-0) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L531-561)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Extended.hs (L170-204)
```haskell
applyHelper ::
  forall blk.
  (HasCallStack, LedgerSupportsProtocol blk) =>
  ( HasCallStack =>
    ComputeLedgerEvents ->
    LedgerCfg LedgerState blk ->
    blk ->
    Ticked LedgerState blk ValuesMK ->
    Except
      (LedgerErr LedgerState blk)
      (LedgerResult blk (LedgerState blk DiffMK))
  ) ->
  ComputeLedgerEvents ->
  LedgerCfg ExtLedgerState blk ->
  blk ->
  Ticked ExtLedgerState blk ValuesMK ->
  Except
    (LedgerErr ExtLedgerState blk)
    (LedgerResult blk (ExtLedgerState blk DiffMK))
applyHelper f opts cfg blk TickedExtLedgerState{..} = do
  ledgerResult <-
    withExcept ExtValidationErrorLedger $
      f
        opts
        (configLedger $ getExtLedgerCfg cfg)
        blk
        tickedLedgerState
  hdr <-
    withExcept ExtValidationErrorHeader $
      validateHeader @blk
        (getExtLedgerCfg cfg)
        ledgerView
        (getHeader blk)
        tickedHeaderState
  pure $ (\l -> ExtLedgerState l hdr) <$> castLedgerResult ledgerResult
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/API.hs (L670-698)
```haskell
replayStartingWith tracer cfg stream initDb from InitDB{initReapplyBlock, currentTip} = do
  res <-
    runExceptT $
      streamAll
        stream
        from
        id
        initDb
        push
  case res of
    Left _ ->
      error $
        "Critical invariant violation: block "
          <> show from
          <> " that was in immutable db is gone before we could open ledgerdb"
    Right v -> pure v
 where
  push :: blk -> db -> m db
  push blk !db = do
    !db' <- initReapplyBlock cfg blk db

    let events =
          inspectLedger
            (getExtLedgerCfg (ledgerDbCfg cfg))
            (currentTip db)
            (currentTip db')

    traceWith tracer (ReplayedBlock (blockRealPoint blk) events)
    return db'
```
