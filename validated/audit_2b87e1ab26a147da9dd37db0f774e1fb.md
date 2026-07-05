### Title
Silent Discard of Envelope-Validation Failure in `revalidateHeader` via `assertWithMsg` No-Op in Production Builds - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs`)

---

### Summary

`assertWithMsg`, the sole mechanism used to enforce the envelope check inside `revalidateHeader`, is a **compile-time no-op** in every production build of the node. When the `asserts` Cabal flag is absent (its default), the function unconditionally returns its second argument and discards the `Either String ()` check result entirely. This is structurally identical to the ERC20 bug: a function that can signal failure returns a value, and the caller never inspects it.

---

### Finding Description

**`assertWithMsg` is a no-op in production.**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs`:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a          -- always reached when flag is off
``` [1](#0-0) 

`ENABLE_ASSERTIONS` is only defined when the `asserts` Cabal flag is set:

```
flag asserts
  description: Enable assertions
  manual: False
  default: False          -- OFF by default
``` [2](#0-1) 

The Nix CI pipeline ships the distributed executables as the `noAsserts` variant, which explicitly empties `cabal/asserts.cabal` at patch time, guaranteeing assertions are absent in every released binary:

```nix
noAsserts = {
  src = lib.mkForce (final.applyPatches {
    ...
    postPatch = ''echo > cabal/asserts.cabal'';
  });
};
``` [3](#0-2) 

**The security-critical call site: `revalidateHeader`.**

`revalidateHeader` is the fast-path header re-validation used whenever a block is *reapplied* (i.e., it was previously validated and is being replayed). It intentionally skips the expensive `updateChainDepState` (KES/VRF crypto) and replaces it with `reupdateChainDepState`. The *only* remaining structural guard — the envelope check — is wrapped in `assertWithMsg`:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $          -- silently ignored in production
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
 where
  envelopeCheck :: Either String ()
  envelopeCheck =
    runExcept $ withExcept show $
      validateEnvelope cfg ledgerView
        (untickedHeaderStateTip st) hdr
``` [4](#0-3) 

`validateEnvelope` enforces: block numbers are consecutive, slots are strictly increasing, and the `prevHash` field matches the predecessor. All three checks are silently discarded in production.

**Where `revalidateHeader` is invoked.**

`reapplyBlockLedgerResult` for `ExtLedgerState` calls `revalidateHeader` unconditionally:

```haskell
reapplyBlockLedgerResult evs cfg blk TickedExtLedgerState{..} =
    (\l -> ExtLedgerState l hdr) <$> castLedgerResult ledgerResult
 where
    ...
    hdr = revalidateHeader (getExtLedgerCfg cfg) ledgerView
                           (getHeader blk) tickedHeaderState
``` [5](#0-4) 

`reapplyBlockLedgerResult` is reached via `tickThenReapply` → `applyBlock` for the `ReapplyVal` / `ReapplyRef` constructors:

```haskell
applyBlock evs cfg ap fo doResolveBlock = case ap of
  ReapplyVal b ->
    withValues b (return . Right . tickThenReapply evs cfg b)
  ...
  ReapplyRef r -> do
    b <- doResolveBlock r
    applyBlock evs cfg (ReapplyVal b) fo doResolveBlock
``` [6](#0-5) 

The `ReapplyVal`/`ReapplyRef` path is taken whenever a block's `RealPoint` is present in the `prevApplied` set, which is populated from all blocks that were previously successfully validated. This path is exercised:

1. **Startup replay** — blocks from the ImmutableDB after the snapshot anchor are streamed and reapplied to reconstruct the ledger state at the immutable tip.
2. **Fork re-selection** — when chain selection switches back to a fork containing previously-validated blocks.

---

### Impact Explanation

During startup replay from a crafted ImmutableDB or snapshot, the node calls `reapplyBlockLedgerResult` for every block between the snapshot anchor and the immutable tip. For each such block, `revalidateHeader` computes the envelope check but its `Left` (failure) branch is unreachable in production. A block with a wrong `blockNo`, a non-monotone `slotNo`, or a mismatched `prevHash` field will be silently accepted, producing a corrupt `ExtLedgerState` that is then used as the anchor for all subsequent chain selection and ledger operations. This constitutes durable use of the wrong ledger state — a **High** impact ChainDB/LedgerDB replay bug.

---

### Likelihood Explanation

**Medium-Low.** The attacker must supply a crafted ImmutableDB or snapshot (the "DB/snapshot input in a local reproduction" entry path explicitly listed in scope). No network peer interaction is required. The node operator would not notice: the node starts normally, the corrupt ledger state is accepted silently, and no error is logged because the check is a no-op. The scenario is realistic for a private-testnet or local reproduction where the data directory is under attacker influence.

---

### Recommendation

Replace `assertWithMsg` in `revalidateHeader` with a proper `Either`-returning check that is enforced unconditionally, independent of the `asserts` flag. The function signature should be changed to:

```haskell
revalidateHeader :: ... -> Either (HeaderError blk) (HeaderState blk)
```

so that callers in `reapplyBlockLedgerResult` are forced by the type system to handle the failure case — exactly the fix the ERC20 report recommends (use `SafeERC20` so the return value cannot be silently ignored). Alternatively, the envelope check should be moved out of `assertWithMsg` and into a hard `throwIO`/`error` path that is not gated on the `asserts` flag.

---

### Proof of Concept

1. Build a `cardano-node` or `db-analyser` binary from the `noAsserts` Nix variant (the default shipped binary).
2. Construct a minimal ImmutableDB containing two blocks where the second block's `blockNo` is not `firstBlockNo + 1` (envelope violation).
3. Start the node pointing at this ImmutableDB with a snapshot anchored before the second block.
4. The node calls `reapplyBlockLedgerResult` → `revalidateHeader` for the second block. `envelopeCheck` returns `Left "..."`, but `assertWithMsg` discards it and returns the `HeaderState` unchanged.
5. The node completes startup with a ledger state whose `HeaderState` reflects the malformed block number, with no error logged.

The root cause is confirmed at:
- `Assert.hs` lines 9–13: `assertWithMsg` is a no-op without `ENABLE_ASSERTIONS`. [1](#0-0) 
- `HeaderValidation.hs` lines 539–561: `revalidateHeader` wraps the only remaining structural check in `assertWithMsg`. [4](#0-3) 
- `Extended.hs` lines 213–227: `reapplyBlockLedgerResult` calls `revalidateHeader` unconditionally on every reapplied block. [5](#0-4) 
- `ouroboros-consensus.cabal` lines 34–37: `asserts` flag defaults to `False`. [2](#0-1) 
- `nix/haskell.nix` lines 94–99: production binaries are built with the `noAsserts` variant. [3](#0-2)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

**File:** ouroboros-consensus.cabal (L34-37)
```text
flag asserts
  description: Enable assertions
  manual: False
  default: False
```

**File:** nix/haskell.nix (L94-99)
```text
      noAsserts = {
        src = lib.mkForce (final.applyPatches {
          name = "consensus-src-no-asserts";
          src = ouroborosConsensusSrc;
          postPatch = ''echo > cabal/asserts.cabal'';
        });
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/Forker.hs (L433-446)
```haskell
applyBlock evs cfg ap fo doResolveBlock = case ap of
  ReapplyVal b ->
    withValues b (return . Right . tickThenReapply evs cfg b)
  ApplyVal b ->
    withValues
      b
      ( \v ->
          case runExcept $ tickThenApply evs cfg b v of
            Left lerr -> pure (Left (AnnLedgerError (castPoint $ getTip v) (blockRealPoint b) lerr))
            Right st -> pure (Right st)
      )
  ReapplyRef r -> do
    b <- doResolveBlock r
    applyBlock evs cfg (ReapplyVal b) fo doResolveBlock
```
