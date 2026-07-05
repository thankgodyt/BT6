### Title
Unconditional Peras Certificate Acceptance Bypasses Quorum Validation, Enabling Adversarial Chain Selection Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally accepts every inbound `PerasCert` from any peer without performing any cryptographic, quorum, or committee verification. This is the live production code path for the Peras certificate diffusion miniprotocol. An unprivileged peer can send a crafted certificate boosting an arbitrary block, causing the receiving node to trigger chain selection in favour of a non-canonical chain.

### Finding Description

The external report describes a vulnerability where a user-controlled parameter (gas price) can be set to zero, making a fee multiplier computation yield zero and bypassing fee collection. The structural analog here is that the certificate content — the attacker-controlled input — is completely ignored by the validation function, making the "check" yield `Right` unconditionally regardless of what the certificate contains.

The degenerate `BlockSupportsPeras` instance in `SupportsPeras.hs` is the only instance in the codebase and is used in production:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This stub is wired directly into the production certificate inbound handler. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

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
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [2](#0-1) 

`processCerts` treats any `Right` result as a valid certificate and immediately adds it to the `PerasCertDB`: [3](#0-2) 

This writer is registered as the live handler for the `perasCertDiffusionProtocol` miniprotocol in `NodeToNode.hs`: [4](#0-3) 

Once a certificate is accepted into the `PerasCertDB`, `chainSelSync` triggers chain selection for the boosted block: [5](#0-4) 

Chain selection uses `wsvTotalWeight`, which adds the `vpcCertBoost` (set to `perasWeight params = PerasWeight 15` by the stub) to the block number of any chain containing the boosted block: [6](#0-5) 

The analog to the external report is exact: just as `protocolFeePaid = gasPrice × protocolFeeMultiplier` yields zero when the user sets `gasPrice = 0` (bypassing fee collection), here the certificate content — the attacker-controlled input — is never checked against any threshold (quorum stake, committee membership, BLS signature), so the "validation cost" is always zero and every certificate passes.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and any round number. Because `validatePerasCert` ignores the certificate content entirely, the certificate is accepted with a boost of `PerasWeight 15`. This boost is added to the total weight of any chain containing the named block during `preferCandidate` comparisons. An adversary can therefore make an honest node prefer a shorter or non-canonical fork over the canonical chain by 15 weight units — equivalent to 15 blocks — without holding any stake, forging any valid block, or breaking any cryptographic primitive. This directly undermines the Peras chain-selection security guarantee.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

### Likelihood Explanation

The attack requires only a TCP connection to the node's peer-to-peer port and the ability to send a well-formed CBOR-encoded `PerasCert` message over the `perasCertDiffusionProtocol` miniprotocol. No stake, no keys, and no prior block knowledge are required. The miniprotocol is enabled for all node-to-node connections whenever the Peras feature flag is active. Likelihood is **High** once Peras is enabled on a live network.

### Recommendation

- **Short term:** Replace the stub `validatePerasCert` with a real implementation that verifies: (1) the certificate's round number is within the valid window, (2) the aggregated BLS/committee signature is valid, and (3) the total stake of the signers exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin` as computed by `stakeAboveThreshold`. Until this is done, the `perasCertDiffusionProtocol` should not be enabled on any network where chain selection integrity matters.
- **Long term:** Enforce a minimum value for `perasQuorumStakeThreshold` (analogous to the report's recommendation for a minimum protocol fee) so that even a misconfigured parameter cannot reduce the quorum check to a no-op.

### Proof of Concept

1. Connect to a Cardano node with Peras enabled as a peer via the node-to-node miniprotocol stack.
2. Send a `PerasCert` message over `perasCertDiffusionProtocol` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of an adversarial fork block>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert cert (PerasWeight 15))` unconditionally.
4. The certificate is added to `PerasCertDB` via `ChainDB.addPerasCertAsync`.
5. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `weightedSelectView` computes `wsvTotalWeight` for any chain containing the adversarial block as `blockNo + 15`, making it preferred over an honest chain of equal block number.
7. The node switches to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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
