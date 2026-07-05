### Title
`validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates Without Cryptographic Validation, Enabling Unauthorized Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, which applies to **all** block types via `instance StandardHash blk => BlockSupportsPeras blk`, implements `validatePerasCert` to unconditionally return `Right` — accepting every inbound certificate without any cryptographic or structural check. This instance is wired directly into the production Peras cert diffusion inbound handler (`hPerasCertDiffusionClient` in `NodeToNode.hs`). Any unprivileged peer can therefore inject arbitrary `PerasCert` objects that boost any block of their choosing, causing the receiving node to trigger chain selection with an attacker-controlled weight boost, potentially switching to a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` lines 350–358, the catch-all instance for all `StandardHash blk` types implements the `validatePerasCert` method as:

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

No signature is checked, no committee membership is verified, no round-number bounds are enforced. Every certificate is unconditionally promoted to `ValidatedPerasCert`.

**Production wiring — the handler is always active:**

`makePerasCertPoolWriterFromChainDB` in `ObjectPool/PerasCert.hs` lines 118–137 passes `validatePerasCert mkPerasParams` as the validator to `processCerts`. `processCerts` (lines 164–185) calls this validator on every inbound cert; because it always returns `Right`, every cert passes and is forwarded to `ChainDB.addPerasCertAsync`.

This writer is passed directly to `objectDiffusionInbound` in `NodeToNode.hs` lines 375–384 (the `hPerasCertDiffusionClient` handler), with no feature flag or version gate:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
```

**Chain-selection effect:**

`chainSelSync` in `ChainSel.hs` lines 483–532 processes each accepted cert. After the "too old" guard at line 490 and the "already on current chain" guard at line 506, if the boosted block is present in the VolatileDB and on a competing fork, `chainSelectionForBlock` is called at line 531 with the full Peras weight boost (`perasWeight = 15` from `mkPerasParams`). This can cause the node to switch to the attacker's chosen fork.

**Exploit path (no privileges required):**

1. Attacker establishes a peer connection to the target node.
2. Attacker sends a `PerasCert` with `pcCertBoostedBlock` pointing to the tip of a competing fork that the target node has in its VolatileDB (e.g., a fork the attacker itself propagated via ChainSync/BlockFetch).
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. Cert is added to the PerasCertDB and forwarded to `chainSelSync`.
5. `chainSelSync` finds the boosted block in the VolatileDB, calls `chainSelectionForBlock` with the boosted weight.
6. The node's chain selection now treats the attacker's fork as heavier by `perasWeight = 15` blocks, potentially switching to it.

---

### Impact Explanation

**Severity: Critical.**

This is a complete bypass of Peras certificate validation — the `validatePerasCert` method of `BlockSupportsPeras` is the sole gate between a peer-supplied certificate and the chain-selection engine. Because it always returns `Right`, any peer can inject certificates that carry the full Peras weight boost (`perasWeight = 15`) for any block they choose. An attacker who can also supply a competing fork (via the standard ChainSync/BlockFetch miniprotocols, which require no privilege) can combine both to make an honest node prefer a non-canonical chain. This directly violates the Peras security assumption that only certificates produced by a legitimate quorum of committee members should influence chain selection.

---

### Likelihood Explanation

**High.** The `PerasCertDiffusion` miniprotocol is unconditionally enabled in `mkHandlers` with no version gate or feature flag. Any peer that negotiates a node-to-node connection can send `PerasCert` messages. The attacker needs only a standard peer connection and knowledge of a block hash in the target node's VolatileDB — both are trivially obtainable via normal protocol interaction.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic validation before the Peras cert diffusion miniprotocol is active on any network. At minimum, gate the `hPerasCertDiffusionClient` handler behind a protocol version or feature flag that is disabled until issue [#120](https://github.com/tweag/cardano-peras/issues/120) is resolved. The `processCerts` function already has the correct rejection logic (lines 174–185) — it only needs a non-trivial validator to be effective.

---

### Proof of Concept

```
Attacker peer                          Target node
     |                                      |
     |-- PerasCertDiffusion connect ------->|
     |                                      |
     |-- MsgObjectIds [round=42] ---------->|  (announce cert for round 42)
     |<- MsgRequestObjects [round=42] ------|  (node requests it)
     |-- MsgObjects [PerasCert{            |
     |     pcCertRound = 42,               |
     |     pcCertBoostedBlock = <fork tip> |
     |   }] -------------------------------->|
     |                                      |
     |                    processCerts called:
     |                    validatePerasCert mkPerasParams cert
     |                    => Right ValidatedPerasCert{vpcBoost=15}
     |                                      |
     |                    ChainDB.addPerasCertAsync cert
     |                                      |
     |                    chainSelSync: boostedBlock in VolatileDB?
     |                    YES => chainSelectionForBlock with +15 weight
     |                    => node switches to attacker's fork
```

The `validatePerasCert` stub at lines 350–358 of `SupportsPeras.hs` is the necessary vulnerable step: it is the only validation gate between the network-received `PerasCert` and the chain-selection engine, and it performs no checks whatsoever. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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
