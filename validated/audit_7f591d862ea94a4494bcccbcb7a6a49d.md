### Title
Unconditional `validatePerasCert` Acceptance Bypasses Peras Certificate Verification, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the only instance in the codebase, used for all block types — implements `validatePerasCert` as an unconditional `Right` return, performing zero cryptographic or structural checks. Any Peras certificate received from an unprivileged peer passes validation, is stored in the `PerasCertDB`, and triggers chain selection. This is the direct analog of the `StaticHyVM` bug: just as `delegatecall` to a non-existent contract silently returns success, `validatePerasCert` silently returns success regardless of the certificate's content.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the sole `BlockSupportsPeras` instance implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

This instance is declared as the universal instance for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

This `validatePerasCert` is called directly in the inbound certificate processing path in `processCerts`, which is the function invoked when certificates arrive from peers via the object diffusion mini-protocol:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

Inside `processCerts`, the validation result gates whether the certificate is added to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer is unconditionally accepted.

Once accepted, the certificate is passed to `ChainDB.addPerasCertAsync`, which enqueues it for chain selection processing:

```haskell
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
``` [5](#0-4) 

The chain selection handler for a Peras certificate (`chainSelSync` with `ChainSelAddPerasCert`) then potentially triggers `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the node's VolatileDB. Because `validatePerasCert` performs no checks — no quorum verification, no committee membership check, no signature verification, no round-number bounds check — the certificate is accepted unconditionally. The Peras boost (`vpcCertBoost = perasWeight params`) is assigned using the static default `mkPerasParams`, giving the attacker-controlled certificate the full protocol-defined weight.

This weight is then factored into chain selection via `getPerasWeightSnapshot`, potentially causing the node to prefer a candidate chain that would otherwise be rejected. The attacker can steer an honest node away from the canonical chain toward an adversarially chosen fork, constituting a chain selection manipulation attack and a bypass of Peras certificate verification.

**Impact class:** Critical — bypass of Peras certificate/voting checks that enables unauthorized certificate acceptance and chain selection manipulation.

---

### Likelihood Explanation

The Peras object diffusion mini-protocol infrastructure is wired into the production `ChainDB` and `NodeKernel`. The `makePerasCertPoolWriterFromChainDB` function is the designated production writer (as opposed to `makePerasCertPoolWriterFromCertDB`, which is documented as test-only). Any peer that can connect and speak the object diffusion mini-protocol can exploit this. No keys, stake, or special privileges are required. The only mitigating factor is that Peras is not yet active on mainnet; however, the code is in production source files and will be active once Peras is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The certificate's round number is within the valid range relative to the current chain tip.
2. The boosted block point is structurally valid.
3. The certificate carries a valid quorum proof (committee membership, signatures, stake threshold).

Until the real implementation is ready, the inbound certificate processing path (`processCerts` / `makePerasCertPoolWriterFromChainDB`) should reject all externally received certificates rather than accepting them unconditionally. The `TODO` comment referencing issue #120 should be treated as a security-blocking item before Peras is enabled on any network.

---

### Proof of Concept

1. Attacker connects to a target node and speaks the Peras object diffusion mini-protocol.
2. Attacker sends a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of a block the attacker wants to boost (e.g., a block on a minority fork present in the node's VolatileDB)
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams}` unconditionally. [7](#0-6) 
5. `partitionEithers` yields `([], [validatedCert])` — no errors, one accepted cert.
6. `addCert` calls `ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)`.
7. `chainSelSync` processes `ChainSelAddPerasCert`, finds the boosted block in the VolatileDB, and calls `chainSelectionForBlock` for it. [8](#0-7) 
8. The node's chain selection now considers the attacker-chosen block as having Peras boost weight, potentially switching to the attacker's preferred fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
