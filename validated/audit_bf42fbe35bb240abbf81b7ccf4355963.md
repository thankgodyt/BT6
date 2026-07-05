### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Peras Certificate, Enabling Unprivileged Chain-Selection Manipulation — (`Ouroboros/Consensus/Block/SupportsPeras.hs` / `ObjectPool/PerasCert.hs`)

---

### Summary

The production `BlockSupportsPeras` instance contains a stub `validatePerasCert` that unconditionally returns `Right` for every certificate. The ObjectDiffusion inbound handler, wired into the production `NodeToNodeV_16` path, calls this stub via `makePerasCertPoolWriterFromChainDB`. Any unprivileged peer can therefore inject an arbitrary `PerasCert` (with any `pcCertBoostedBlock`) that will be accepted, stored in the `PerasCertDB`, and used to trigger `chainSelectionForBlock` for the attacker-chosen block, adding `perasWeight = 15` to that chain fragment and potentially causing the node to switch to a fork it would otherwise not prefer.

---

### Finding Description

**Step 1 — Stub validator, always `Right`** [1](#0-0) 

The universal `instance StandardHash blk => BlockSupportsPeras blk` (marked "TODO: degenerate instance for all blks to get things to compile") implements `validatePerasCert` as:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No signature check, no committee membership check, no round-range check — every certificate is unconditionally promoted to `ValidatedPerasCert`.

**Step 2 — Production writer uses the stub** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` to `processCerts`. Because the stub always returns `Right`, `processCerts` never reaches the `throw (PerasCertValidationError errs)` branch; every inbound cert is timestamped and forwarded to `ChainDB.addPerasCertAsync`.

**Step 3 — Wired into the production NodeToNodeV_16 handler** [3](#0-2) 

`hPerasCertDiffusionClient` calls `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB systemTime getChainDB` as the `ObjectPoolWriter`. The `NodeToNodeVersion` parameter is accepted but ignored (`_version`) inside `objectDiffusionInbound`.

**Step 4 — Chain selection triggered for the attacker-chosen block** [4](#0-3) 

`chainSelSync` for `ChainSelAddPerasCert` stores the cert in `PerasCertDB`, then — if the `pcCertBoostedBlock` is present in the `VolatileDB` — calls `chainSelectionForBlock` for that block. The boosted chain now carries an extra `perasWeight = 15` units, which can tip chain selection in favour of the attacker's preferred fork.

---

### Impact Explanation

An unprivileged peer connecting via `NodeToNodeV_16` can send a `PerasCert` naming any block hash already in the node's `VolatileDB`. Because `validatePerasCert` never rejects anything, the cert is stored and chain selection is re-run with the fake boost applied. If the attacker's target fork is within `perasWeight` units of the current selection, the node will switch to it. This is a **chain-selection manipulation** attack: the attacker can cause an honest node to prefer a non-canonical fork without possessing any stake, committee membership, or cryptographic keys.

Impact category: **High** — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

- `NodeToNodeV_16` is listed in `supportedNodeToNodeVersions` for `CardanoBlock`, so the ObjectDiffusion miniprotocol is reachable from any peer that negotiates that version.
- `latestReleasedNodeVersion` currently returns `NodeToNodeV_15`, so this code may not yet be active on mainnet nodes — but it is present in the production source tree and will become active when `NodeToNodeV_16` is promoted.
- The attack requires no special privileges: any node-to-node peer can send ObjectDiffusion messages.
- The boosted block must already be in the VolatileDB, which is a mild precondition easily satisfied by first sending the target block via BlockFetch.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies committee membership, quorum signatures, and round-range constraints before returning `Right`. Until that implementation is complete, the ObjectDiffusion cert-inbound path should either be disabled (gated behind a feature flag) or the `processCerts` call should be replaced with a hard rejection of all inbound certs. The TODO at `cardano-peras/issues/120` tracks this work.

---

### Proof of Concept

```
1. Connect to a target node that supports NodeToNodeV_16.
2. Via BlockFetch, ensure block B (on a minority fork) is in the target's VolatileDB.
3. Via the ObjectDiffusion miniprotocol, send a PerasCert:
     { pcCertRound = <any round>, pcCertBoostedBlock = point(B) }
4. processCerts calls validatePerasCert mkPerasParams, which returns Right unconditionally.
5. addPerasCertAsync enqueues ChainSelAddPerasCert.
6. chainSelSync adds the cert to PerasCertDB and calls chainSelectionForBlock for B.
7. The chain through B now carries +15 weight; if it was within 15 of the current
   selection, the node switches to the minority fork.
```

Reproducible locally with `io-sim` by constructing a mock peer that sends a crafted `PerasCert` over a connected channel to `objectDiffusionInbound` backed by `makePerasCertPoolWriterFromChainDB`.

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
