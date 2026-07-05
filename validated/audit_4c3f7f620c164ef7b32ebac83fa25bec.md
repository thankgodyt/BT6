Let me investigate the relevant code paths to evaluate this vulnerability claim.

I have traced the full call path and examined all relevant production code. Here is my assessment.

---

### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peras Certificate, Enabling Forged-Cert Chain Divergence — (`Block/SupportsPeras.hs`)

### Summary

The production `validatePerasCert` implementation is a stub that always returns `Right` regardless of the certificate's aggregate BLS signature or voter eligibility proofs. A peer can send a `PerasCert` with a zeroed or arbitrary aggregate signature over the NodeToNode Peras cert diffusion protocol; the cert passes "validation," is stored in the `PerasCertDB`, its boost weight is added to the `PerasWeightSnapshot`, and `chainSelectionForBlock` is triggered for the boosted block. If the boosted block exists in the VolatileDB on a fork, the node may switch to that fork.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

Every `PerasCert blk` unconditionally becomes a `ValidatedPerasCert blk` with full boost weight. No aggregate BLS signature check, no voter eligibility check, no quorum check.

**Network entrypoint — `makePerasCertPoolWriterFromChainDB`:** [2](#0-1) 

This is wired directly into the NodeToNode protocol handler: [3](#0-2) 

`processCerts` calls `validateCert` (the stub) on each inbound cert; if all pass (they always do), each is forwarded to `addCert`: [4](#0-3) 

**Chain selection path — `chainSelSync` (ChainSelAddPerasCert):** [5](#0-4) 

The only guard is a slot-age check (`pointSlot boostedBlock < AF.anchorToSlotNo immTip`). If the boosted block is recent enough, `PerasCertDB.addCert` is called (updating the `PerasWeightSnapshot`), then `chainSelectionForBlock` is triggered for the boosted block.

**Weight comparison — `preferCandidate` / `wsvTotalWeight`:** [6](#0-5) 

`wsvTotalWeight` sums `BlockNo` and `wsvWeightBoost` (from the `PerasWeightSnapshot`). A forged cert with a large boost can make a shorter fork appear heavier than the honest chain.

**The real crypto verification exists but is never called:**

The `WFALS` and `EveryoneVotes` committee implementations contain proper `implVerifyCert` functions that verify aggregate BLS signatures and VRF outputs: [7](#0-6) 

These are never invoked by the production `validatePerasCert` path.

### Impact Explanation

An unprivileged peer sends a `PerasCert` with a forged (e.g., zeroed) aggregate BLS signature boosting a block on an adversary-controlled fork. The stub validation passes. The cert's boost weight is added to the `PerasWeightSnapshot`. `chainSelectionForBlock` runs for the boosted fork block. `constructPreferableCandidates` → `preferAnchoredCandidate` compares `wsvTotalWeight` and, if the boost is large enough, returns `ShouldSwitch`. The node switches to the adversary's fork. This is an irreversible chain divergence from the honest chain, matching the Critical scope: bypass of Peras certificate signature validation enabling unauthorized certificate acceptance and consensus safety failure.

### Likelihood Explanation

The Peras cert diffusion protocol is wired into the production NodeToNode handler. Any peer that speaks the protocol can send an arbitrary `PerasCert`. The stub is the only `validatePerasCert` implementation in the codebase (the `instance StandardHash blk => BlockSupportsPeras blk` overlapping instance covers all block types). The exploit requires only: (1) a fork block in the target node's VolatileDB, and (2) a crafted cert boosting that block. No key material, no stake, no admin access required.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature via `verifyAggregateVoteSignature` (as done in `implVerifyCert` in `WFALS.hs` and `EveryoneVotes.hs`).
2. Verifies voter eligibility (seat membership, VRF outputs for non-persistent voters).
3. Checks quorum threshold against the stake distribution.

Until the real implementation is in place, the Peras cert diffusion inbound handler should reject all inbound certs (or the protocol should not be enabled in production builds).

### Proof of Concept

In a local two-node `io-sim` or integration test:
1. Node A has a fork block `F` in its VolatileDB (slot recent enough to pass the `immTip` check).
2. Peer B sends a `PerasCert { pcRoundNo = r, pcBoostedBlock = point(F), pcVoters = ..., pcSignature = zeroed }` via the Peras cert diffusion protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. `addPerasCertAsync` → `chainSelSync` → `PerasCertDB.addCert` → weight snapshot updated → `chainSelectionForBlock` for `F`.
5. Assert: node A's selected chain tip is now `F` (the adversary's fork), despite the cert having a zeroed aggregate signature.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L550-562)
```haskell
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```
