### Title
`revalidateHeader` silently drops all envelope and cryptographic validation in production builds — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs`)

---

### Summary

`revalidateHeader` is a second, parallel implementation of `validateHeader` that wraps its entire envelope check inside `assertWithMsg`, a macro that compiles to a no-op when the `asserts` flag is not set (the default). In production builds, `revalidateHeader` therefore performs **zero** envelope validation and **zero** KES/VRF cryptographic checks. When the LedgerDB replays blocks from a crafted or corrupted ImmutableDB, every block passes `revalidateHeader` unconditionally, allowing durable acceptance of a wrong ledger state.

---

### Finding Description

`validateHeader` performs two mandatory checks:

1. `validateEnvelope` — block number, slot monotonicity, prev-hash chain, checkpoint match, and HFC `additionalEnvelopeChecks` (era identity check).
2. `updateChainDepState` — full KES signature and VRF proof verification for Praos. [1](#0-0) 

`revalidateHeader` is documented as "same as `validateHeader` but used when the header has been validated before." It replaces `updateChainDepState` with `reupdateChainDepState` (which explicitly skips KES and VRF) and wraps the envelope check in `assertWithMsg`: [2](#0-1) 

`assertWithMsg` is defined as:

```haskell
assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
``` [3](#0-2) 

`ENABLE_ASSERTIONS` is only defined when the `asserts` Cabal flag is enabled, which defaults to `False`: [4](#0-3) 

In production builds (flag off), `assertWithMsg` is a pure identity function. The `envelopeCheck` value is computed but its result is unconditionally discarded. `revalidateHeader` therefore reduces to:

```haskell
revalidateHeader cfg _ hdr st =
  HeaderState (NotOrigin (getAnnTip hdr)) (reupdateChainDepState ...)
```

No envelope check. No KES. No VRF.

`revalidateHeader` is called from `reapplyBlockLedgerResult` in `ExtLedgerState`, which is the code path used during LedgerDB initialization when replaying blocks from the ImmutableDB: [5](#0-4) 

The ImmutableDB's own validation (`validateChunk`) checks CRC32 checksums and hash-chain continuity, but does **not** verify consensus-level fields such as block number, slot number, or the HFC era tag embedded in the header. A block with a valid hash chain but a wrong block number, wrong slot, or a forged era tag (claiming to be a Conway block when it is a Shelley block) passes ImmutableDB validation and is then replayed through `revalidateHeader` without any of those fields being checked.

The Praos `reupdateChainDepState` confirms it skips all cryptographic checks: [6](#0-5) 

The HFC `additionalEnvelopeChecks` — which verifies that the header's era matches the current ledger view — is part of `validateEnvelope` and is therefore also silently skipped: [7](#0-6) 

---

### Impact Explanation

**High.** A crafted ImmutableDB block (or a sequence of blocks delivered via a compromised snapshot/ImmutableDB distribution) that passes structural CRC32 and hash-chain checks but carries invalid consensus fields (wrong block number, wrong slot, wrong era tag, forged KES/VRF) will be replayed by `revalidateHeader` without any rejection. The resulting `ExtLedgerState` is written durably into the LedgerDB. The node then operates on a permanently wrong ledger state — wrong stake distribution, wrong epoch info, wrong era — without any error or warning. This matches the "LedgerDB/snapshot corruption/replay bug that causes durable use of the wrong ledger state" impact class.

---

### Likelihood Explanation

**Low-to-Medium.** The attack requires delivering a crafted block into the ImmutableDB or a crafted snapshot to the node's data directory. This is not directly reachable over the network in a standard deployment, but is explicitly within scope as a "DB/snapshot input in a local reproduction." The structural mismatch is also a latent hazard: any future refactoring that calls `revalidateHeader` on a block that has not previously passed `validateHeader` (e.g., during a new chain-selection optimization) would silently bypass all validation in production with no compile-time or runtime warning.

---

### Recommendation

- **Short term:** Remove the `assertWithMsg` wrapper from `revalidateHeader` and enforce the envelope check unconditionally (not just in debug builds). The envelope check is cheap compared to KES/VRF; there is no performance justification for omitting it.
- **Long term:** Maintain a single validation path. If `reupdateChainDepState` must skip KES/VRF for performance, the envelope check should remain mandatory and non-conditional. Add a type-level or runtime precondition that `revalidateHeader` can only be called with a block that carries a proof of prior `validateHeader` success, preventing the two code paths from diverging silently.

---

### Proof of Concept

1. Build `cardano-node` or any consumer of `ouroboros-consensus` **without** the `asserts` flag (the default production build).
2. Craft an ImmutableDB chunk file containing a block whose header has a valid hash chain and valid CRC32 but carries an incorrect `BlockNo` (e.g., `BlockNo 9999` instead of the expected sequential value) or a mismatched HFC era tag.
3. Place the crafted chunk in the node's ImmutableDB directory.
4. Start the node. During LedgerDB initialization, `reapplyBlockLedgerResult` is called for each ImmutableDB block, which calls `revalidateHeader`.
5. In production, `assertWithMsg envelopeCheck` is a no-op; the wrong `BlockNo` and era tag are never checked.
6. `reupdateChainDepState` updates the nonce state without verifying KES or VRF.
7. The node completes initialization with a durably wrong `ExtLedgerState` and continues operating on it. [8](#0-7) [9](#0-8) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Assert.hs (L1-15)
```haskell
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}

module Ouroboros.Consensus.Util.Assert (assertWithMsg) where

import GHC.Stack (HasCallStack)
import Ouroboros.Consensus.Util.RedundantConstraints

assertWithMsg :: HasCallStack => Either String () -> a -> a
#if ENABLE_ASSERTIONS
assertWithMsg (Left msg) _ = error msg
#endif
assertWithMsg _ a = a
 where
  _ = keepRedundantConstraint (Proxy @HasCallStack)
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

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L491-530)
```haskell
  -- Re-update the chain dependent state as a result of processing a header.
  --
  -- This consists of:
  -- - Update the last applied block hash.
  -- - Update the evolving and (potentially) candidate nonces based on the
  --   position in the epoch.
  -- - Update the operational certificate counter.
  reupdateChainDepState
    _cfg@( PraosConfig
             PraosParams{praosRandomnessStabilisationWindow}
             ei
           )
    b
    slot
    tcs =
      cs
        { praosStateLastSlot = NotOrigin slot
        , praosStateLabNonce = prevHashToNonce (Views.hvPrevHash b)
        , praosStateEvolvingNonce = newEvolvingNonce
        , praosStateCandidateNonce =
            if slot +* Duration praosRandomnessStabilisationWindow < firstSlotNextEpoch
              then newEvolvingNonce
              else praosStateCandidateNonce cs
        , praosStateOCertCounters =
            Map.insert hk n $ praosStateOCertCounters cs
        }
     where
      epochInfoWithErr =
        hoistEpochInfo
          (either throw pure . runExcept)
          ei
      firstSlotNextEpoch = runIdentity $ do
        EpochNo currentEpochNo <- epochInfoEpoch epochInfoWithErr slot
        let nextEpoch = EpochNo $ currentEpochNo + 1
        epochInfoFirst epochInfoWithErr nextEpoch
      cs = tickedPraosStateChainDepState tcs
      eta = vrfNonceValue (Proxy @c) $ Views.hvVrfRes b
      newEvolvingNonce = praosStateEvolvingNonce cs ⭒ eta
      OCert _ n _ _ = Views.hvOCert b
      hk = hashKey $ Views.hvVK b
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger.hs (L336-360)
```haskell
instance CanHardFork xs => ValidateEnvelope (HardForkBlock xs) where
  type OtherHeaderEnvelopeError (HardForkBlock xs) = HardForkEnvelopeErr xs

  additionalEnvelopeChecks
    tlc
    (HardForkLedgerView transition hardForkView) =
      \(HardForkHeader (OneEraHeader hdr)) ->
        case Match.matchNS hdr (State.tip hardForkView) of
          Left mismatch ->
            throwError $
              HardForkEnvelopeErrWrongEra . MismatchEraInfo $
                Match.bihcmap proxySingle singleEraInfo ledgerViewInfo mismatch
          Right matched ->
            hcollapse $ hcizipWith proxySingle aux cfgs matched
     where
      ei :: EpochInfo (Except PastHorizonException)
      ei =
        State.epochInfoPrecomputedTransitionInfo
          (hardForkLedgerConfigShape $ configLedger tlc)
          transition
          hardForkView

      cfgs :: NP TopLevelConfig xs
      cfgs = distribTopLevelConfig ei tlc

```
