### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection via Fake Weight Boosts - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or semantic validation whatsoever. This function is wired directly into the live inbound Peras certificate handler (`makePerasCertPoolWriterFromChainDB` → `processCerts`), which is reachable by any unprivileged peer via the ObjectDiffusion mini-protocol. An attacker can inject arbitrary crafted `PerasCert` objects that will be accepted and added to the ChainDB, triggering chain selection with artificial Peras weight boosts and potentially causing an honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The `BlockSupportsPeras` instance for all `StandardHash blk` types (the universal production instance) implements `validatePerasCert` as a stub that always succeeds:

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

No BLS aggregate signature verification, no committee membership check, no VRF eligibility proof, and no round-number plausibility check is performed. Every certificate, regardless of content, is returned as `ValidatedPerasCert` with the full configured `perasWeight` boost.

**Production inbound handler uses this stub directly:**

`makePerasCertPoolWriterFromChainDB` — the production writer used for peer-supplied certificates — passes `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

**`processCerts` gates admission entirely on this stub:**

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validateCert` (bound to the stub) always returns `Right`, the `([], validatedCerts)` branch is always taken and every peer-supplied certificate is forwarded to `ChainDB.addPerasCertAsync`.

**`addPerasCertAsync` triggers chain selection with the fake boost:**

`chainSelSync` processes the queued certificate, adds it to `cdbPerasCertDB`, and then calls `chainSelectionForBlock` for the boosted block, potentially switching the node to a fork that now appears heavier due to the injected weight: [4](#0-3) 

The `PerasWeightSnapshot` used during chain comparison is derived from the `PerasCertDB`, which now contains the attacker's certificate: [5](#0-4) 

### Impact Explanation

An unprivileged peer can inject one `PerasCert` per Peras round number (the only deduplication check is `Set.member roundNo alreadyInDb`). Each accepted certificate assigns a `perasWeight` boost (default: 15, per `mkPerasParams`) to an attacker-chosen block. If the attacker targets a block on a minority fork, the artificial boost can make that fork appear heavier than the honest chain, causing the victim node to switch away from the canonical chain. This is a **chain selection integrity failure** triggered entirely by peer-supplied, unauthenticated data — matching the allowed impact category: *"Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance"* and *"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is wired into the production `NodeKernel` and is reachable by any peer that connects to the node. No stake, keys, or privileged access are required. The only barrier is knowing the wire format of `PerasCert`, which is defined in the public codebase. The attack requires one connection and one crafted message per target round.

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic validation before the Peras certificate diffusion path is enabled in production. At minimum, the gate should verify:
1. The aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregate public key of the claimed committee members.
2. Each voter's VRF eligibility proof for the given round and epoch nonce.
3. That the total stake of the claimed voters meets the quorum threshold.

Until real validation is implemented, the `makePerasCertPoolWriterFromChainDB` inbound handler should reject all externally supplied certificates (e.g., by substituting a `const (Left PerasValidationErr)` guard), or the ObjectDiffusion server for Peras certificates should not be started.

### Proof of Concept

1. Attacker connects to a victim node as a normal peer.
2. Attacker identifies a block hash `B` on a minority fork that is `perasWeight` (15) blocks behind the honest tip.
3. Attacker constructs a `PerasCert { pcCertRound = <any unused round>, pcCertBoostedBlock = B }` with arbitrary content — no valid signature required.
4. Attacker sends the certificate via the ObjectDiffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` unconditionally. [6](#0-5) 
6. The certificate is forwarded to `ChainDB.addPerasCertAsync`.
7. `chainSelSync` adds the cert to `cdbPerasCertDB` and calls `chainSelectionForBlock` for block `B`.
8. Chain selection now sees block `B`'s fork as having weight `length(fork) + 15`, potentially exceeding the honest chain's weight.
9. The victim node switches to the minority fork, diverging from the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
