### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that always returns `Right` (success) regardless of certificate content. Because this validator is wired directly into the production NTN Peras certificate diffusion inbound handler, any unprivileged peer can inject arbitrary Peras certificates that are accepted, stored in the ChainDB, and used to boost arbitrary blocks during chain selection — without any cryptographic or structural verification.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gating function that must approve a certificate before it is stored. The universal default instance, which applies to all block types including `CardanoBlock` unless overridden, implements this function as a no-op stub:

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

This stub is not isolated to tests. It is the validator passed directly to `processCerts` inside `makePerasCertPoolWriterFromChainDB`, the production pool writer used by the NTN handler:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, if all pass (which they always do with the stub), adds them to the ChainDB: [3](#0-2) 

This pool writer is registered as `hPerasCertDiffusionClient` in `mkHandlers`, which is wired into the `initiatorAndResponder` bundle for all NTN connections: [4](#0-3) [5](#0-4) 

Once a certificate is accepted, `chainSelSync` in `ChainSel.hs` processes it and triggers chain selection for the boosted block: [6](#0-5) 

Chain selection then uses `totalWeightOfFragment`, which adds the Peras boost weight to the chain length when comparing candidates: [7](#0-6) 

The boost weight assigned to every accepted certificate is `perasWeight params` — a non-zero protocol parameter — meaning each injected certificate materially shifts the chain selection outcome.

---

### Impact Explanation

An unprivileged NTN peer can craft a `PerasCert` pointing to any block hash and any round number. Because `validatePerasCert` always returns `Right`, the certificate passes `processCerts` and is stored in the ChainDB. The ChainDB then triggers chain selection for the boosted block. If the attacker's target block is on a fork, the injected boost weight can cause the honest node to prefer the attacker's fork over the canonical chain, constituting a **chain selection manipulation** that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

This maps to: **High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

The Peras certificate diffusion miniprotocol is compiled into the production binary and registered unconditionally in `initiatorAndResponder` for all NTN connections. Any peer that successfully completes the NTN handshake can send `PerasCert` objects. No stake, key material, or special privilege is required. The attack requires only the ability to open a standard NTN connection and send a crafted CBOR-encoded certificate batch. The TODO comments confirm this is a known incomplete state, but the code is live in the production diffusion path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that checks:
1. The certificate's round number is within the valid range relative to the current chain tip.
2. The boosted block point corresponds to a known, valid block.
3. The certificate carries a valid quorum of committee member signatures (the core cryptographic check).

Until real validation is implemented, the Peras certificate inbound handler should be disabled or gated behind a feature flag that is off by default in production builds — directly analogous to the Solflare recommendation to remove development/localhost origins from the production allow-list.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker opens a standard NTN connection to the target node and completes version negotiation.
2. Attacker sends a `MsgObjects` message on the `PerasCertDiffusion` miniprotocol containing a crafted `PerasCert { pcCertRound = R, pcCertBoostedBlock = <fork tip point> }`.
3. `objectDiffusionInbound` → `opwAddObjects` → `processCerts` is called with `validatePerasCert mkPerasParams` as the validator.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally. [8](#0-7) 
5. `processCerts` calls `addCert` (i.e., `ChainDB.addPerasCertAsync`) with the fake validated certificate. [9](#0-8) 
6. `chainSelSync` processes the certificate, looks up the boosted block in `VolatileDB`, and calls `chainSelectionForBlock` for it. [10](#0-9) 
7. Chain selection now computes `totalWeightOfFragment` for the fork, which includes the injected boost, potentially making the fork heavier than the honest chain. [11](#0-10) 
8. The node switches to the attacker's fork.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1268)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
        , perasVoteDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasVoteDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasVoteDiffusionServer version responderCtx))
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
