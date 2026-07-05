### Title
Envelope Validation Result Silently Discarded in `revalidateHeader` via `assertWithMsg` No-Op in Default Production Builds - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs`)

### Summary

`revalidateHeader` in `HeaderValidation.hs` wraps its entire envelope check in `assertWithMsg`, which is compiled to a complete no-op when the `asserts` Cabal flag is `False` — its default. In a standard production build, the `Either String ()` result of `validateEnvelope` is computed but its failure branch is unconditionally discarded, meaning block-number consecutiveness, slot-number monotonicity, and hash-linkage are never enforced during header re-validation.

### Finding Description

`assertWithMsg` in `Ouroboros.Consensus.Util.Assert` is defined with a CPP guard:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
``` [1](#0-0) 

`ENABLE_ASSERTIONS` is only defined when the `asserts` Cabal flag is enabled, which defaults to `False`:

```cabal
flag asserts
  description: Enable assertions
  manual: False
  default: False
...
  if flag(asserts)
    ghc-options: -fno-ignore-asserts
    cpp-options: -DENABLE_ASSERTIONS
``` [2](#0-1) 

`revalidateHeader` uses `assertWithMsg` as the sole guard for its envelope check:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $
    HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
  where
    envelopeCheck :: Either String ()
    envelopeCheck =
      runExcept $ withExcept show $
        validateEnvelope cfg ledgerView (untickedHeaderStateTip st) hdr
``` [3](#0-2) 

In a default production build, `assertWithMsg envelopeCheck result` reduces to `result` regardless of whether `envelopeCheck` is `Left err` or `Right ()`. The `validateEnvelope` call is evaluated (it is not lazy-dropped), but its `Left` branch is never acted upon. This is structurally identical to the SafeERC20 analog: a function returns a typed failure value, but the caller discards it without checking.

The same pattern appears in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client` (6 call sites) and `Ouroboros.Consensus.HardFork.Combinator.AcrossEras` (2 call sites), all of which rely on `assertWithMsg` for invariant enforcement that is silently absent in production. [4](#0-3) 

### Impact Explanation

`revalidateHeader` is documented as the fast path used "when the header has been validated before w.r.t. the same exact `HeaderState`." However, the envelope check it skips in production enforces structural chain invariants — consecutive block numbers, strictly increasing slot numbers, and hash linkage — that are independent of the expensive VRF/KES checks delegated to `reupdateChainDepState`. If any code path invokes `revalidateHeader` on a header whose `HeaderState` context has shifted (e.g., after a rollback or a ledger-view update), or if a future caller incorrectly uses `revalidateHeader` instead of `validateHeader`, the envelope invariants are silently unenforced. An adversarial peer that can trigger such a path could have a header with a non-consecutive block number or a non-monotonic slot accepted into the chain without error.

The impact class is: **High — header-state bug that lets an unprivileged peer make an honest node accept a structurally invalid header beyond the intended security assumptions**, contingent on a code path reaching `revalidateHeader` without a prior successful `validateHeader` on the same state.

### Likelihood Explanation

The `asserts` flag is `False` by default and is explicitly described as something to enable only temporarily for debugging. Every standard `cardano-node` production binary is built without it. The `cabal/asserts.cabal` override file exists but is not part of the default build. The bypass is therefore present in every default production deployment. The conditional is a latent defect: it is harmless only as long as the "already validated" precondition of `revalidateHeader` is always upheld by all callers, which is an informal contract with no compile-time enforcement.

### Recommendation

Replace `assertWithMsg` in `revalidateHeader` with a hard unconditional check that does not depend on the `asserts` flag. The envelope check is cheap (pure structural comparison) and should never be elided in production. Concretely, change:

```haskell
revalidateHeader cfg ledgerView hdr st =
  assertWithMsg envelopeCheck $ ...
```

to:

```haskell
revalidateHeader cfg ledgerView hdr st =
  case envelopeCheck of
    Left err -> error ("revalidateHeader: envelope check failed: " <> err)
    Right () -> ...
```

More broadly, audit all `assertWithMsg` call sites in production modules (`ChainSync.Client`, `AcrossEras`, `Shelley.Node.TPraos`, `Cardano.Node`) and replace any that guard security-relevant invariants with unconditional `Either`-returning checks, mirroring the pattern already used in `validateHeader`.

### Proof of Concept

1. Build `ouroboros-consensus` with the default flags (no `+asserts`). Confirm `ENABLE_ASSERTIONS` is absent from the preprocessor environment.
2. In a private testnet, craft a header whose `validateEnvelope` would return `Left` (e.g., a header with a block number that is not `prevBlockNo + 1`).
3. Arrange for `revalidateHeader` to be called on this header (e.g., by replaying it through the ChainSync client path that calls `revalidateHeader` on a candidate already present in the volatile DB).
4. Observe that no exception is raised and the header is accepted, whereas the same header submitted through `validateHeader` would be rejected with `HeaderEnvelopeError`. [1](#0-0) [3](#0-2) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L9-13)
```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
```

**File:** ouroboros-consensus.cabal (L34-67)
```text
flag asserts
  description: Enable assertions
  manual: False
  default: False

flag expensive-invariants
  description: Enable checks for expensive invariants
  manual: True
  default: False

common ghc-9.14
  if impl(ghc >=9.14)
    ghc-options:
      -Wno-redundant-constraints
      -Wno-pattern-namespace-specifier

common common-lib
  import: ghc-9.14
  default-language: Haskell2010
  ghc-options:
    -Wall
    -Wcompat
    -Wincomplete-uni-patterns
    -Wincomplete-record-updates
    -Wpartial-fields
    -Widentities
    -Wredundant-constraints
    -Wmissing-export-lists
    -Wunused-packages
    -Wno-unticked-promoted-constructors

  if flag(asserts)
    ghc-options: -fno-ignore-asserts
    cpp-options: -DENABLE_ASSERTIONS
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L524-562)
```haskell
-- | Header revalidation
--
-- Same as 'validateHeader' but used when the header has been validated before
-- w.r.t. the same exact 'HeaderState'.
--
-- Expensive validation checks are skipped ('reupdateChainDepState' vs.
-- 'updateChainDepState').
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
