### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or protocol-level checks. This stub is wired directly into the production node-to-node `PerasCertDiffusion` mini-protocol handler via `makePerasCertPoolWriterFromChainDB`. Any unprivileged peer can therefore inject an arbitrary `PerasCert` that boosts the weight of any block in chain selection, potentially causing an honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — stub validation always succeeds**

`SupportsPeras.hs` lines 350–358 define the only deployed instance of `validatePerasCert`:

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

No signature check, no quorum check, no round-number check, no eligibility check — every certificate is unconditionally accepted and assigned a boost of `perasWeight params`.

**Production wiring — the stub is the live inbound handler**

`PerasCert.hs` lines 118–137 (`makePerasCertPoolWriterFromChainDB`) pass `validatePerasCert mkPerasParams` as the validation callback for all inbound certificates:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`NodeToNode.hs` lines 375–384 wire this writer into the live `hPerasCertDiffusionClient` handler that runs for every connected peer:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
```

**End-to-end exploit path**

1. Attacker connects to a node via the `PerasCertDiffusion` mini-protocol (no credentials required).
2. Attacker sends a crafted `PerasCert { pcCertRound = r, pcCertBoostedBlock = <point on adversarial fork> }`.
3. `processCerts` (`PerasCert.hs` lines 164–173) calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`.
5. `chainSelSync` (`ChainSel.hs` lines 483–535) adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
6. `chainSelectionForBlock` reads the `PerasWeightSnapshot` (which now includes the attacker-injected boost of `PerasWeight 15`) and passes it to `preferAnchoredCandidate`.
7. Chain selection may now prefer the adversarially boosted fork over the honest chain.

### Impact Explanation

An unprivileged peer can inject a `PerasCert` for any block reachable in the VolatileDB, granting it an unearned weight boost of `PerasWeight 15` in chain selection. Because Peras weight is additive and compared against the honest chain's weight, a sufficiently crafted certificate can flip chain selection toward a non-canonical fork. This is a bypass of Peras certificate verification that enables unauthorized certificate acceptance and chain-selection manipulation by an external attacker — matching the **High** impact tier: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

**High.** The `PerasCertDiffusion` mini-protocol is enabled in the production `NodeToNode` handler for every peer connection. No key material, stake, or operator access is required. The attacker needs only to establish a standard node-to-node connection and send a single well-formed `PerasCert` CBOR message. The stub is present in the main branch of the production codebase with no runtime guard disabling it.

### Recommendation

1. **Do not ship `validatePerasCert` as a stub in any build that enables `PerasCertDiffusion`.** The function must verify the aggregate BLS signature over the committee votes, confirm quorum (total stake ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`), and check that the round number and boosted block satisfy the protocol rules before returning `Right`.
2. Until full validation is implemented, gate the `hPerasCertDiffusionClient` handler behind a feature flag that is disabled by default, so the stub cannot be reached from the network.
3. Resolve the `TODO` at `PerasCert.hs` lines 103 and 126 by threading the actual `PerasCfg blk` from the node configuration into `makePerasCertPoolWriterFromChainDB` instead of using the hardcoded `mkPerasParams`.

### Proof of Concept

```
-- Attacker node (no stake, no keys):
1. Establish a NodeToNode connection to the target node.
2. Negotiate a protocol version that includes PerasCertDiffusion.
3. Encode and send via the ObjectDiffusion inbound protocol:
     PerasCert
       { pcCertRound      = PerasRoundNo <any round>
       , pcCertBoostedBlock = <Point of a block on an adversarial fork
                               currently in the target's VolatileDB>
       }
4. processCerts calls (validatePerasCert mkPerasParams cert)
   => always returns Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })
5. addPerasCertAsync enqueues the cert; chainSelSync triggers
   chainSelectionForBlock for the boosted block.
6. preferAnchoredCandidate now sees the adversarial fork with +15 weight;
   if that tips the comparison, the node switches to the adversarial chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```
