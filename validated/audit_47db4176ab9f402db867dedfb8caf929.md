### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero field-level checks. Any unprivileged peer can craft and inject a `PerasCert` with an arbitrary round number and boosted-block point; the certificate will pass "validation," be stored in `PerasCertDB`, and trigger chain selection that applies the certificate's boost weight to the attacker-chosen block. This is the direct analog of the external report's missing denomination check: a critical per-item field validation is absent when iterating over and accepting protocol objects from the network.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must verify a received Peras certificate before it is stored or acted upon:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only deployed instance — the universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this as:

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

No field of `cert` is inspected. The function never returns `Left`. The `PerasCert` record carries `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`; neither is checked against the current round, the known vote tally, a quorum proof, or any signature. [2](#0-1) 

This stub is the **only** `BlockSupportsPeras` instance in the repository (the comment explicitly labels it "degenerate instance for all blks to get things to compile"). [3](#0-2) 

---

### Impact Explanation

`validatePerasCert` is called on every inbound certificate in both production pool-writer paths:

```haskell
(validatePerasCert mkPerasParams)   -- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams)   -- makePerasCertPoolWriterFromChainDB
``` [4](#0-3) [5](#0-4) 

Because `validatePerasCert` always succeeds, `processCerts` never throws `PerasCertInboundException` (which would disconnect the peer). Every certificate is timestamped and forwarded to `PerasCertDB.addCert`, then to `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. [6](#0-5) 

Inside `chainSelSync`, the certificate's `pcCertBoostedBlock` is looked up in the VolatileDB. If the block is present, `chainSelectionForBlock` is invoked with the certificate's boost weight (`vpcCertBoost = perasWeight params`), potentially causing the node to switch to the fork containing the attacker-chosen block: [7](#0-6) 

An adversary can therefore:
1. Craft a `PerasCert` naming any block hash currently in the VolatileDB.
2. Send it over the Peras certificate mini-protocol.
3. Force the honest node to re-run chain selection with an artificial boost on the attacker's preferred fork, causing a chain switch that would not occur under honest Peras rules.

This is a **bypass of Peras certificate/vote verification** that enables unauthorized certificate acceptance and non-canonical chain selection — matching the "Critical: Bypass of Peras voting or certificate checks" impact category.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is wired into the production `NodeKernel` path via `makePerasCertPoolWriterFromChainDB`. Any peer that can open a connection to the node can send certificates. No stake, key material, or privileged access is required. The attacker only needs to know a block hash present in the target node's VolatileDB (trivially obtained via the ChainSync protocol). Exploitation requires no brute force and no cryptographic material.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that:
1. Verifies the certificate's round number falls within the expected current or recent Peras round window.
2. Verifies that a quorum of valid, individually-signed votes for `(pcCertRound, pcCertBoostedBlock)` exists (or that the certificate carries an aggregate signature over those votes).
3. Verifies the boosted block point is consistent with the chain's history.

Until a real implementation is available, the certificate diffusion mini-protocol should not be enabled in production builds, or `validatePerasCert` should return `Left PerasValidationErr` by default (fail-closed) rather than `Right` (fail-open).

---

### Proof of Concept

```
Attacker node A connects to honest node H.
A observes block B (hash bHash, slot s) on H's chain via ChainSync.
A crafts:
  cert = PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = BlockPoint s bHash }
A sends cert over the Peras certificate mini-protocol.

On H:
  processCerts calls validatePerasCert mkPerasParams cert
  → always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
  → cert stored in PerasCertDB
  → addPerasCertAsync enqueues ChainSelAddPerasCert
  → chainSelSync looks up bHash in VolatileDB, finds it
  → chainSelectionForBlock runs with boost weight applied to the fork containing B
  → H may switch to A's preferred fork
```

The `validatePerasCert` stub is at: [1](#0-0) 

The inbound processing path that calls it without any fallback check is at: [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
