### Title
Peras Certificate Validation Bypass via Unconditional `Right` Return Enables Unauthorized Chain-Selection Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The default `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Because this stub is wired directly into the production certificate ingest path (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject an arbitrary `PerasCert` that is accepted without validation, stored in the `PerasCertDB`, and used to trigger chain selection with a full `PerasWeight` boost for an attacker-chosen block.

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must approve every inbound Peras certificate before it enters the node's state. The catch-all instance that covers all block types is:

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

No signature is verified, no quorum proof is checked, no round-number bounds are enforced, and no block-existence check is performed. The function simply wraps the raw peer-supplied `PerasCert` in a `ValidatedPerasCert` and returns `Right`. [1](#0-0) 

This stub is the validator passed directly to `processCerts` in both production pool-writer constructors:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` treats a `Right` result as a fully validated certificate and immediately forwards it to `addCert` / `addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the cert for `chainSelSync`, which looks up the cert's `boostedBlock` in the `VolatileDB` and, if found, calls `chainSelectionForBlock` with the full `PerasWeight` boost applied: [4](#0-3) 

The `PerasWeight` boost is a configurable additive weight (`perasWeight params`) that is added to the chain density of the boosted block's chain during chain selection. A fraudulent cert pointing to any block in the VolatileDB therefore inflates that block's chain weight by `perasWeight`, potentially making a shorter or adversarially-chosen fork appear heavier than the honest chain. [5](#0-4) 

The analog to the ERC20 report is exact: just as `transfer` returning `false` was never checked (silent success), `validatePerasCert` always returns `Right` (silent acceptance), so the caller's rejection branch is structurally unreachable.

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` containing any `pcCertRound` and any `pcCertBoostedBlock` that happens to be present in the target node's VolatileDB. The cert bypasses all validation, is stored in the `PerasCertDB`, and triggers chain selection for the attacker-chosen block with a full `PerasWeight` boost. If the boosted block is on a fork, the honest node may switch to that fork, constituting an unauthorized chain-selection manipulation. This is a **Critical** bypass of Peras certificate verification that enables unauthorized certificate acceptance and a **High** chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer. No stake, key material, or privileged access is required. The attacker only needs to know (or guess) a block hash present in the target's VolatileDB, which is publicly observable via the ChainSync protocol. The `validatePerasCert mkPerasParams` call is unconditional in the production code path, so the bypass is triggered on every inbound cert from every peer.

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that at minimum:
1. Verifies the aggregate BLS/committee signature over `(pcCertRound, pcCertBoostedBlock)`.
2. Confirms the signing committee reached the configured quorum threshold.
3. Checks that `pcCertRound` is within the acceptable window relative to the current slot.
4. Verifies that the committee members are drawn from the correct epoch's stake distribution.

Until a real implementation is available, the node should refuse to accept externally-sourced Peras certificates entirely (return `Left PerasValidationErr` unconditionally) rather than accept them all.

### Proof of Concept

1. Connect to a target node via the object-diffusion mini-protocol for Peras certificates.
2. Observe (via ChainSync) a block hash `H` on a minority fork in the target's VolatileDB.
3. Send a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s H }` for any round `r` not yet in the target's `PerasCertDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
5. The cert is enqueued via `addPerasCertAsync`.
6. `chainSelSync` retrieves block `H` from the VolatileDB and calls `chainSelectionForBlock` with the `PerasWeight` boost.
7. If `perasWeight` is large enough relative to the honest chain's density advantage, the node switches to the fork containing `H`.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
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
