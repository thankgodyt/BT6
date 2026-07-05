### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. This instance is wired directly into the production inbound Peras certificate processing path, meaning any peer can inject crafted certificates that are accepted without scrutiny and subsequently influence chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate for accepting Peras certificates received over the network. The sole concrete instance in the codebase is a degenerate catch-all:

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

This instance is not confined to tests. The production inbound handler `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` directly to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
``` [2](#0-1) 

`processCerts` applies `validateCert` to every inbound certificate and throws `PerasCertValidationError` only when at least one cert returns `Left`. Because `validatePerasCert` always returns `Right`, the error branch is unreachable and every certificate—regardless of content—is accepted, timestamped, and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` feeds into `chainSelSync`, which adds the certificate to `PerasCertDB`, computes a weight boost of `perasWeight = 15` (from `mkPerasParams`) for the boosted block, and triggers `chainSelectionForBlock`: [4](#0-3) 

Chain selection then uses `preferAnchoredCandidate`, which—when the `PerasWeightSnapshot` is non-empty—compares fragments by `weightedSelectView`, giving the adversarially boosted block a 15-unit advantage over unboosted honest blocks: [5](#0-4) 

The Peras certificate diffusion client and server are both wired into the production `NodeToNode` handlers, making this path reachable by any connected peer: [6](#0-5) 

The analog to the Salty.IO report is exact: just as `performUpkeep` dispatches rewards only to `stakingRewards` (Liquidity) and completely overlooks the Collateral contract, `validatePerasCert` dispatches the certificate to `Right` and completely overlooks all actual validation logic (BLS aggregate signature, committee membership, quorum threshold, round-number bounds). In both cases a function that should route through a second critical component silently skips it.

---

### Impact Explanation

An unprivileged peer crafts a `PerasCert` naming any `PerasRoundNo` and any `Point blk` as the boosted block. The certificate passes `validatePerasCert` unconditionally, is stored in `PerasCertDB`, and grants the named block a weight boost of 15 in `preferAnchoredCandidate`. If the adversary's chain tip is the boosted block, the honest node may switch to that chain even when it is shorter or otherwise non-canonical, constituting a **bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain-selection manipulation** (Critical per the allowed scope).

---

### Likelihood Explanation

The Peras certificate diffusion protocol is active in the production `NodeToNode` stack. Any peer that can open a connection can send crafted certificates. No keys, stake, or operator access are required. The only prerequisite is that the node is running a build that includes the Peras diffusion handlers, which is the case for the current codebase.

---

### Recommendation

1. **Short term**: Implement real cryptographic and semantic validation inside `validatePerasCert`—at minimum BLS aggregate signature verification over `(pcCertRound, pcCertBoostedBlock)`, committee membership checks, and quorum-threshold enforcement—before the degenerate instance is reachable from any live diffusion path.
2. **Long term**: Replace the universal `instance StandardHash blk => BlockSupportsPeras blk` catch-all with per-era instances that carry the actual validation logic, mirroring the pattern used for `LedgerSupportsProtocol`. Gate the Peras diffusion handlers behind an era check so they are unreachable until a proper instance is in place.

---

### Proof of Concept

```
1. Attacker connects to a target node as a standard peer.
2. Attacker sends a PerasCert message via the Peras certificate diffusion
   mini-protocol, setting:
     pcCertRound      = <any round number>
     pcCertBoostedBlock = <point of an adversarial block already in the
                          target node's VolatileDB>
3. The node's aPerasCertDiffusionClient receives the message and calls
   makePerasCertPoolWriterFromChainDB → processCerts.
4. processCerts calls validatePerasCert mkPerasParams cert, which returns
   Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }) with no
   checks performed.
5. The cert is forwarded to ChainDB.addPerasCertAsync → chainSelSync.
6. chainSelSync adds the cert to PerasCertDB and calls
   chainSelectionForBlock for the boosted block.
7. preferAnchoredCandidate now scores the adversarial chain 15 weight
   units higher than an equally-long honest chain.
8. The node switches to the adversarial chain, diverging from the honest
   network.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
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
