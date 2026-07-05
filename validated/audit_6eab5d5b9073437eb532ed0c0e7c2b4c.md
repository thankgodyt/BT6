### Title
Unconditional `validatePerasCert` Stub Enables Unauthorized Certificate Acceptance and Chain-Selection Manipulation via PerasCertDiffusion Miniprotocol — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance (the only compiled instance) implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or committee-membership checks. This stub is wired directly into the production NodeToNode `PerasCertDiffusion` miniprotocol. Any peer that can negotiate `NodeToNodeV_16` can send a `PerasCert` with an arbitrary round number and arbitrary boosted block point, have it accepted into the `PerasCertDB`, and trigger `chainSelectionForBlock` for the boosted block — without any valid aggregate BLS signature or committee quorum.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

The `StandardHash blk` instance at line 320 is the only compiled instance (per the TODO at line 318). Its `validatePerasCert` at lines 353–358 unconditionally returns:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No signature, no BLS aggregate check, no committee-membership check, no round-number bounds check.

**Production inbound path — `processCerts`:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function. Since `validatePerasCert` always returns `Right`, `processCerts` always reaches the "all certs valid" branch and calls `ChainDB.addPerasCertAsync`. [3](#0-2) 

**NodeToNode wiring — `hPerasCertDiffusionClient`:** [4](#0-3) 

`hPerasCertDiffusionClient` is wired unconditionally into both `initiator` and `initiatorAndResponder` bundles: [5](#0-4) 

**Chain selection trigger — `chainSelSync`:** [6](#0-5) 

Once the cert is added to `PerasCertDB`, if the boosted block is present in the `VolatileDB`, `chainSelectionForBlock` is called for it — giving it a `perasWeight` boost of 15 (per `mkPerasParams`) in chain selection.

---

### Impact Explanation

An unprivileged peer that can negotiate `NodeToNodeV_16` (enabled via `srnEnableInDevelopmentVersions` or when this version becomes released) can:

1. Send a `PerasCert` pointing to any block in the `VolatileDB` as the "boosted" block.
2. The cert bypasses all validation and is accepted into `PerasCertDB`.
3. `chainSelectionForBlock` is triggered for the attacker-chosen block with a weight boost of 15, potentially causing the node to switch to an adversarially chosen fork.
4. The invariant that only certificates backed by a valid quorum of authorized committee members may be accepted is completely violated.

This matches the allowed impact scope: **Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance**, and **High — chain selection manipulation letting an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The exploit requires `NodeToNodeV_16` to be negotiated. In production today this requires `srnEnableInDevelopmentVersions = True` (per `limitToLatestReleasedVersion` at line 1160–1165 of `Node.hs`). However:

- The code is fully compiled and wired into the production binary with no compile-time guard.
- Any private testnet or development deployment with `srnEnableInDevelopmentVersions = True` is immediately exploitable.
- Once `NodeToNodeV_16` is promoted to a released version, this becomes exploitable on any node running this codebase. [7](#0-6) 

---

### Recommendation

1. **Immediate**: Gate `validatePerasCert` so that it returns `Left PerasValidationErr` (i.e., rejects all certs) until real BLS aggregate signature and committee-membership verification is implemented. This is safer than the current stub that accepts everything.
2. **Short-term**: Implement real certificate validation (BLS aggregate signature verification, committee membership check, round-number bounds) before `NodeToNodeV_16` is promoted to a released version.
3. **Defense-in-depth**: Add a compile-time or runtime assertion that the degenerate stub instance is never used in a context where `addPerasCertAsync` can trigger chain selection.

---

### Proof of Concept

On a local two-node testnet with `srnEnableInDevelopmentVersions = True` (unmodified code):

1. Start two nodes that negotiate `NodeToNodeV_16`.
2. From the attacker node, craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block known to be in the victim's `VolatileDB`.
3. Send it via the `PerasCertDiffusion` miniprotocol.
4. Observe via tracing that `ChainSelectionForBoostedBlock` fires on the victim node and chain selection runs for the attacker-chosen block.

Property-test confirmation (no network needed):

```haskell
prop_validatePerasCertAlwaysRight :: PerasCert TestBlock -> Bool
prop_validatePerasCertAlwaysRight cert =
  isRight (validatePerasCert mkPerasParams cert)
-- This property holds for ALL inputs, confirming zero validation.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1263)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node.hs (L1153-1165)
```haskell
    -- Limit the node version unless srnEnableInDevelopmentVersions is set
    limitToLatestReleasedVersion ::
      forall k v.
      Ord k =>
      ((Maybe NodeToNodeVersion, Maybe NodeToClientVersion) -> Maybe k) ->
      Map k v ->
      Map k v
    limitToLatestReleasedVersion prj =
      if srnEnableInDevelopmentVersions
        then id
        else case prj $ latestReleasedNodeVersion (Proxy @blk) of
          Nothing -> id
          Just version -> Map.takeWhileAntitone (<= version)
```
