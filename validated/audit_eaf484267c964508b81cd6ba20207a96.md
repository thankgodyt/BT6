### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the default `BlockSupportsPeras` instance is a stub that unconditionally accepts every inbound Peras certificate without performing any cryptographic or semantic checks. Because the Peras certificate diffusion mini-protocol is already wired into the production node-to-node stack, an unprivileged peer can inject a crafted certificate that boosts an arbitrary block, causing the honest node to prefer a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must be passed before a certificate is admitted to the `PerasCertDB` and used to influence chain selection. The default instance, which is the only instance in the codebase and is used in the production diffusion path, is:

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

This function ignores the certificate's content entirely and always returns `Right`. No committee membership check, no BLS aggregate signature verification, no check that the boosted block belongs to the correct era or chain, and no check that the round number is consistent with the current epoch — none of these are performed.

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then calls this validator on every certificate received from a peer, and if it returns `Right` (which it always does), the certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Inside `chainSelSync`, the accepted certificate is stored in `PerasCertDB` and immediately triggers `chainSelectionForBlock` for the block named in the certificate's `pcCertBoostedBlock` field: [4](#0-3) 

The weight boost from the fraudulent certificate is then reflected in `implGetWeightSnapshot`, which feeds directly into chain selection comparisons: [5](#0-4) 

The `PerasCertDB` implementation itself also carries a matching TODO acknowledging that non-trivial validation is absent: [6](#0-5) 

The node-to-node diffusion stack is fully wired: `aPerasCertDiffusionClient` and `aPerasCertDiffusionServer` are active in the production `NodeToNode` module, so the attack surface is reachable from any connected peer. [7](#0-6) 

---

### Impact Explanation

A peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to a block on a weaker or adversarial fork. Because `validatePerasCert` always succeeds, the certificate is stored and its weight boost is applied during chain selection. If the boosted block is on a fork that would otherwise lose the selection comparison, the injected boost can flip the outcome, causing the honest node to switch to a non-canonical chain. This satisfies the **High** impact criterion: a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The attack requires only a network connection to the target node — no stake, no keys, no operator access. The Peras certificate diffusion mini-protocol is already active in the node-to-node stack. The attacker needs to send a single well-formed CBOR-encoded `PerasCert` message with a `pcCertBoostedBlock` pointing to a block already in the node's VolatileDB. The `processCerts` function will accept it unconditionally. Likelihood is **High** once Peras is enabled on a live network.

---

### Recommendation

Implement real cryptographic and semantic validation inside `validatePerasCert` before the Peras diffusion layer is enabled on any network where the outcome matters. At minimum, the validation must:

1. Verify the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)` against the committee's public keys for that round.
2. Verify that each voter's eligibility proof is valid for the claimed seat index and stake distribution.
3. Verify that the quorum threshold is met.
4. Verify that `pcCertBoostedBlock` refers to a block in the correct era and that its slot falls within the expected Peras round window.

Until this is done, the Peras certificate diffusion server should be disabled or the `processCerts` path should reject all inbound certificates.

---

### Proof of Concept

1. Connect to a target node running this codebase via the node-to-node Peras certificate diffusion mini-protocol.
2. Obtain the hash and slot of any block `B` currently in the node's VolatileDB on a weaker fork (e.g., a fork that would lose chain selection without a boost).
3. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = BlockPoint <slot> <hash of B>`.
4. Send the certificate to the node. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
5. `chainSelSync` stores the certificate and calls `chainSelectionForBlock` for `B`.
6. `implGetWeightSnapshot` now includes a weight boost for `B`'s chain, potentially causing the node to switch to the weaker fork. [1](#0-0) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1000-1043)
```haskell
  aPerasCertDiffusionClient ::
    NodeToNodeVersion ->
    ExpandedInitiatorContext addrNTN PeerTrustable m ->
    Channel m bPCD ->
    m (NodeToNodeInitiatorResult, Maybe bPCD)
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

  aPerasCertDiffusionServer ::
    NodeToNodeVersion ->
    ResponderContext addrNTN ->
    Channel m bPCD ->
    m ((), Maybe bPCD)
  aPerasCertDiffusionServer
    version
    ResponderContext{rcConnectionId = them}
    channel = do
      labelThisThread "PerasCertDiffusionServer"
      runPeerWithLimits
        (TraceLabelPeer them `contramap` tPerasCertDiffusionTracer)
        (cPerasCertDiffusionCodec (mkCodecs version))
        blPerasCertDiffusion
        timeLimitsObjectDiffusion
        channel
        ( objectDiffusionOutboundPeer
            (hPerasCertDiffusionServer version them)
        )
```
