### Title
`revalidateHeader` Envelope Check Silently Discarded in Production Builds via `assertWithMsg` No-Op — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs`)

---

### Summary

`assertWithMsg` is a CPP-gated function that becomes an unconditional no-op in any build that does not define `ENABLE_ASSERTIONS`. In `revalidateHeader`, the entire envelope validation result — which checks block-number consecutiveness, slot monotonicity, and hash linkage — is passed to `assertWithMsg` and silently discarded in production. This is the direct structural analog of the Amp.sol ignored-return-value bug: a critical check is computed but its failure branch is never reachable in production, so the check provides zero enforcement.

---

### Finding Description

**`assertWithMsg` is a compile-time no-op in production:** [1](#0-0) 

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

Without `ENABLE_ASSERTIONS`, the second equation matches unconditionally: the `Either String ()` argument is evaluated but its `Left` branch is never acted upon. The function is identical to `const id`.

**`revalidateHeader` relies entirely on `assertWithMsg` for its envelope check:** [2](#0-1) 

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  chainDepState' =
    reupdateChainDepState ...   -- skips expensive VRF/KES checks by design

  envelopeCheck :: Either String ()
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
```

`validateEnvelope` checks block-number consecutiveness, slot strict-monotonicity, and hash linkage. In production, `assertWithMsg envelopeCheck` reduces to `id`, so a header that fails `validateEnvelope` (wrong block number, non-increasing slot, broken hash chain) is accepted without error.

`reupdateChainDepState` additionally skips all expensive consensus checks (VRF proof, KES signature) by the protocol's own contract: [3](#0-2) 

> "It is worth noting that since we already know that the header is valid w.r.t. the provided ChainDepState, no validation checks should be performed."

So `revalidateHeader` in production performs **no validation at all**.

**Primary production caller — `reapplyBlockLedgerResult`:** [4](#0-3) 

```haskell
reapplyBlockLedgerResult evs cfg blk TickedExtLedgerState{..} =
    (\l -> ExtLedgerState l hdr) <$> castLedgerResult ledgerResult
  where
    ...
    hdr = revalidateHeader (getExtLedgerCfg cfg) ledgerView
                           (getHeader blk) tickedHeaderState
```

`reapplyBlockLedgerResult` is the path taken when replaying blocks from the ImmutableDB (e.g., on node startup, after a crash, or when loading a ledger snapshot and replaying the suffix). The ImmutableDB's own validation (`validateChunk`) only checks CBOR checksums and intra-chunk hash linkage — it does not re-run full consensus envelope validation. Therefore, a block stored in the ImmutableDB with a crafted envelope (wrong block number, non-monotone slot) will be replayed through `reapplyBlockLedgerResult` → `revalidateHeader` with zero enforcement of those invariants in production.

---

### Impact Explanation

**Severity: High** — ChainDB/ImmutableDB replay bug that causes durable use of the wrong ledger state.

A node that replays its ImmutableDB (startup, crash recovery, snapshot reload) will silently accept blocks with invalid envelopes — wrong block numbers, non-strictly-increasing slots, broken hash linkage — and incorporate them into the canonical `ExtLedgerState`. The resulting ledger state is permanently divergent from the honest chain. Because the `ExtLedgerState` (including `headerState`) is what drives subsequent chain selection and header validation, the node's view of the chain is irrecoverably corrupted without any error being raised.

---

### Likelihood Explanation

The precondition for `revalidateHeader` — "this header was previously validated against this exact `HeaderState`" — is enforced only by programmer discipline, not by the type system or any runtime check in production. Any future refactor, snapshot-format change, or ImmutableDB migration that violates this precondition will silently corrupt ledger state. Additionally, a crafted on-disk ImmutableDB input (in scope per the prompt) can directly trigger this path. Likelihood is **Medium**: requires either a crafted DB input or a latent precondition violation, but the absence of any production-time guard makes the window permanent.

---

### Recommendation

Replace `assertWithMsg` in `revalidateHeader` with a proper `Either`-returning check that is enforced at runtime regardless of build flags, or promote `revalidateHeader` to return `Except (HeaderError blk) (HeaderState blk)` and enforce the envelope check unconditionally, matching the contract of `validateHeader`. At minimum, document explicitly that `revalidateHeader` provides **no** validation guarantees in production builds, so callers do not rely on it for security.

---

### Proof of Concept

1. Compile `ouroboros-consensus` without `-DENABLE_ASSERTIONS` (the default production build).
2. Confirm `assertWithMsg` reduces to `\_ a -> a` — the `Left` branch is unreachable.
3. Construct an ImmutableDB chunk containing a block whose `blockNo` is not `prevBlockNo + 1` (invalid envelope).
4. Start a node pointing at this ImmutableDB. On startup, `reapplyBlockLedgerResult` is called for each ImmutableDB block.
5. Observe that `revalidateHeader` returns a `HeaderState` for the invalid block without raising any error, and the node's `ExtLedgerState` is built on top of the invalid header — permanently diverging from the honest chain with no log output or exception. [1](#0-0) [5](#0-4) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
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
