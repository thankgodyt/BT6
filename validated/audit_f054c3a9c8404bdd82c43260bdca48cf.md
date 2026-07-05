Let me look at the Outbound.hs file and check how the object diffusion is wired up in production, and also check `mkPerasParams` and `perasWeight`.

### Title
Stub `validatePerasCert` Unconditionally Accepts Any PerasCert, Enabling Unprivileged Peer to Manipulate Chain Selection via Fake Boost — (`Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` catch-all instance's `validatePerasCert` implementation is a development stub that unconditionally returns `Right` for every inbound certificate, assigning it a boost of `perasWeight mkPerasParams = PerasWeight 15`. This stub is wired directly into the production node-to-node Peras cert diffusion handler. An unprivileged peer can send a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any valid minority-fork block, have it accepted without any committee-signature or quorum check, stored in the `PerasCertDB`, and then trigger `chainSelectionForBlock` for the boosted block — potentially causing the honest node to switch to the minority fork if it is within 15 blocks of the current tip.

---

### Finding Description

**Root cause — stub validator:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
```

No committee membership check, no aggregate signature verification, no quorum weight check — every cert is accepted.

**Boost value:** [2](#0-1) 

`perasWeight = PerasWeight 15` in `mkPerasParams`.

**Inbound path — production node-to-node handler:** [3](#0-2) 

`hPerasCertDiffusionClient` calls `makePerasCertPoolWriterFromChainDB systemTime getChainDB`, which uses `validatePerasCert mkPerasParams` as the validator and `ChainDB.addPerasCertAsync` as the sink.

**`processCerts` accepts the cert and enqueues it:** [4](#0-3) 

`processCerts` calls `validatePerasCert mkPerasParams` (always `Right`), timestamps the cert, and calls `void . ChainDB.addPerasCertAsync chainDB`.

**`chainSelSync` processes the cert and triggers chain selection:** [5](#0-4) 

After adding the cert to the `PerasCertDB`, if the boosted block is present in the `VolatileDB`, `chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment` is called. If the block is not yet present, the boost is recorded in the `PerasWeightSnapshot` and applied when the block later arrives via BlockFetch.

**Chain selection uses the weight snapshot:** [6](#0-5) 

`chainSelectionForBlock` reads `getPerasWeightSnapshot` and passes it to `constructPreferableCandidates`, which uses `preferAnchoredCandidate bcfg weights curChain` to decide whether the minority fork is preferred.

**Weight comparison:** [7](#0-6) 

`wsvTotalWeight = blockNo + weightBoost`. A minority fork at height H with a fake cert boost of 15 beats the current chain at height H' if `H + 15 > H'`, i.e., the minority fork is at most 14 blocks shorter.

**Ledger validation still applies:** [8](#0-7) 

`validateCandidate` calls `LedgerDB.validateFork`, so the minority fork blocks must pass full ledger validation. This means the attacker cannot make the node accept an *invalid* chain — only a *valid* minority fork that would otherwise lose the weight comparison.

---

### Impact Explanation

An unprivileged peer can inject a `PerasCert` with no real committee backing, causing an honest node to prefer a valid minority fork over the canonical chain whenever the minority fork is within 15 blocks of the current tip. This violates the core Peras invariant: only certificates backed by a quorum of committee signatures should influence chain selection. The node may roll back up to 15 blocks of canonical chain history and adopt a minority fork, breaking chain-selection safety beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras cert diffusion mini-protocol is wired into the production `NodeToNode.hs` handler without any feature flag or version gate that disables it. Any peer running a compatible node version can send `PerasCert` messages. Valid minority forks (blocks produced by legitimate slot leaders that lost the natural chain-selection race) exist routinely in any live network. The attacker only needs to know the hash of such a block in the target node's `VolatileDB` — obtainable via ChainSync — and send a single cert message. The boost of 15 is large enough to be practically exploitable during normal operation.

---

### Recommendation

1. **Immediate**: Gate the Peras cert diffusion inbound handler behind a feature flag or `NodeToNodeVersion` check that is disabled until `validatePerasCert` is fully implemented.
2. **Short-term**: Implement real committee-signature and quorum-weight validation in `validatePerasCert` before enabling the protocol in any environment where untrusted peers can connect.
3. **Tracking**: Issues `tweag/cardano-peras#73` and `tweag/cardano-peras#120` already track this; they should be treated as security-blocking before the protocol is enabled.

---

### Proof of Concept

```
Setup:
  - Honest node N with current chain tip at height H (e.g., H = 100)
  - Valid minority fork block B at height H-5 = 95, hash = <minority_hash>
    (B is in N's VolatileDB, received via BlockFetch from another peer)

Attack:
  1. Attacker connects to N via node-to-node protocol (Peras cert diffusion enabled)
  2. Attacker sends PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint 95 <minority_hash> }
  3. processCerts calls validatePerasCert mkPerasParams cert → Right (boost = 15)
  4. addPerasCertAsync enqueues the cert
  5. chainSelSync processes it:
     - boostedBlock slot >= immutable tip slot → not too old
     - boostedBlock not on current chain → proceed
     - boostedBlock IS in VolatileDB → chainSelectionForBlock called
  6. constructPreferableCandidates:
     - minority fork total weight = 95 + 15 = 110 > current chain weight = 100
     - ShouldSwitch returned
  7. validateCandidate: minority fork passes ledger validation (valid blocks)
  8. Node switches to minority fork, rolling back 5 blocks of canonical history

Assert: N's tip is now on the minority fork, with no real committee quorum having voted for it.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-634)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1300-1307)
```haskell
validateCandidate chainSelEnv chainDiff@(ChainDiff rollback suffix) neHeaders onSuccess =
  LedgerDB.validateFork
    lgrDB
    traceUpdate
    blockCache
    rollback
    neHeaders
    onSuccess
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
