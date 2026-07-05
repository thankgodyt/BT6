### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Selection Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound `PerasCert`, performing zero cryptographic or semantic checks. Any unprivileged peer connected via the `perasCertDiffusionProtocol` miniprotocol can inject a crafted certificate that boosts an arbitrary block, causing the receiving node to trigger chain selection for that block and potentially prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate every inbound Peras certificate before it is stored and acted upon. The universal catch-all instance — explicitly marked as a degenerate placeholder — implements this gate as an unconditional `Right`:

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

This instance is declared as `instance StandardHash blk => BlockSupportsPeras blk`, making it the operative instance for all block types, including Cardano blocks, until a more specific instance is provided. [2](#0-1) 

The inbound certificate pipeline in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the validation function:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` then accepts every certificate that passes this non-check and forwards it to `ChainDB.addPerasCertAsync`: [4](#0-3) 

`chainSelSync` then triggers chain selection for the block boosted by the accepted certificate: [5](#0-4) 

The full attacker-controlled entry path is:

```
peer → perasCertDiffusionProtocol → aPerasCertDiffusionClient
     → objectDiffusionInbound (hPerasCertDiffusionClient)
     → makePerasCertPoolWriterFromChainDB → processCerts
     → validatePerasCert (always Right)
     → ChainDB.addPerasCertAsync → chainSelSync
     → chainSelectionForBlock (boosted block)
``` [6](#0-5) [7](#0-6) 

---

### Impact Explanation

A certificate carries a `pcCertBoostedBlock :: Point blk` that directly influences chain selection weight. Because `validatePerasCert` performs no checks — no quorum verification, no committee membership check, no signature verification, no round-number bounds check — an attacker can craft a certificate pointing to any block already present in the node's VolatileDB. `chainSelSync` will then run `chainSelectionForBlock` for that block, potentially causing the node to switch to a non-canonical fork that the attacker has pre-seeded with valid (but non-preferred) blocks.

This matches the **High** impact category: a chain-selection bug triggered by an unprivileged peer that makes an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions. [8](#0-7) 

---

### Likelihood Explanation

The `perasCertDiffusionProtocol` is an active miniprotocol exposed to every connected peer in both initiator and responder modes. [9](#0-8) 

No authentication, stake proof, or committee membership is required to send a `PerasCert` message. The stub is in the production library path (`ouroboros-consensus/src/ouroboros-consensus/`), not a test library, and is the only instance in scope for all block types. Any peer that can establish a node-to-node connection can exploit this.

---

### Recommendation

1. **Do not ship `validatePerasCert` as an unconditional `Right`** in any code path reachable from the live miniprotocol. Until the real implementation is ready, replace the stub with an unconditional `Left PerasValidationErr` (reject all) so that the protocol is safely inert rather than silently permissive.
2. Implement the full certificate validation: verify committee membership, aggregate signature/quorum proof, round-number bounds, and that the boosted block point is plausible.
3. Mirror the same fix for `validatePerasVote` — the production `hPerasVoteDiffusionClient` handler already passes `pure (PerasVoteStakeDistr mempty)`, which causes all votes to be rejected, but this is an accidental safety net, not a deliberate guard. [10](#0-9) 

---

### Proof of Concept

1. Connect to a target node as a peer (standard node-to-node handshake).
2. Via the `perasCertDiffusionProtocol` channel, send a `PerasCert` with:
   - `pcCertRound` = any `PerasRoundNo`
   - `pcCertBoostedBlock` = the `Point` of a block the attacker has previously diffused into the target's VolatileDB on a minority fork.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. `ChainDB.addPerasCertAsync` stores the certificate; `chainSelSync` fires `chainSelectionForBlock` for the boosted block.
5. If the boosted block's chain (augmented by the Peras boost weight) now scores higher than the current selection, the node switches to the attacker's fork. [11](#0-10) [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L119-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-409)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
            version
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1005-1023)
```haskell
  aPerasCertDiffusionClient
    version
    ExpandedInitiatorContext
      { eicConnectionId = them
      , eicControlMessage = controlMessageSTM
      }
    channel = do
      labelThisThread "PerasCertDiffusionClient"
      ((), trailing) <-
        runPipelinedPeerWithLimits
          (TraceLabelPeer them `contramap` tPerasCertDiffusionTracer)
          (cPerasCertDiffusionCodec (mkCodecs version))
          blPerasCertDiffusion
          timeLimitsObjectDiffusion
          channel
          ( objectDiffusionInboundPeerPipelined
              (hPerasCertDiffusionClient version controlMessageSTM them)
          )
      return (NoInitiatorResult, trailing)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1265)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
        , perasVoteDiffusionProtocol =
            ( InitiatorAndResponderProtocol
```
