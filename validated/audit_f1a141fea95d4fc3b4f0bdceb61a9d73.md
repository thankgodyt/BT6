### Title
Peras Certificate Validation Unconditionally Returns Success, Allowing Any Peer to Inject Arbitrary Chain-Boosting Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or structural checks. Because this function is wired directly into the live node-to-node `PerasCertDiffusion` mini-protocol handler, any unprivileged peer can send a crafted `PerasCert` that boosts an arbitrary block in the VolatileDB, causing the receiving node to prefer a non-canonical fork over the honest chain.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must approve inbound Peras certificates before they are stored and used in chain selection. The degenerate instance that covers all block types is:

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

This is not a stub behind a feature flag — it is the live `instance StandardHash blk => BlockSupportsPeras blk` that applies to every block type in the system. [2](#0-1) 

The function is called directly from `makePerasCertPoolWriterFromChainDB`, which is the production pool writer used by the node-to-node handler:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` passes every certificate through `validateCert`; because `validatePerasCert` always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`. [4](#0-3) 

The node-to-node handler wires this pool writer directly to the live `PerasCertDiffusion` mini-protocol:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

Once a certificate is accepted, `chainSelSync` adds it to the `PerasCertDB` and, if the boosted block is present in the VolatileDB, immediately triggers chain selection for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

Chain selection uses `wsvTotalWeight = blockNo + weightBoost`, where `weightBoost` is accumulated from all accepted certificates. The default `perasWeight` is **15**, meaning a single injected certificate adds 15 units of weight to the targeted block. [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

An attacker who controls a single peer connection can craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block currently in the target node's VolatileDB (e.g., a block on a minority fork). Because `validatePerasCert` performs no checks whatsoever — no committee membership verification, no cryptographic signature check, no round-number validity check, no quorum check — the certificate is accepted unconditionally. The boosted block gains 15 units of weight, which can flip chain selection away from the honest longest chain to the attacker-chosen fork. Multiple certificates can be injected to accumulate arbitrary weight. This directly violates the Praos/Peras chain-selection invariant that only legitimately certified blocks should receive a boost.

---

### Likelihood Explanation

Any node that has the Peras `PerasCertDiffusion` mini-protocol enabled and accepts inbound connections is reachable. The attacker needs only a single peer connection and knowledge of a block hash present in the target's VolatileDB (obtainable via ChainSync). No stake, no keys, and no privileged access are required. The attack is deterministic and requires no brute force.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the certificate's aggregate signature against the expected committee's aggregate verification key.
2. Checks that the `pcCertRound` is within the valid window (not expired, not from the future).
3. Verifies that the `pcCertBoostedBlock` corresponds to a block that satisfies `perasBlockMinSlots` age.
4. Confirms that the signers collectively meet the `perasQuorumStakeThreshold`.

Until the full implementation is ready, the stub should be replaced with a function that unconditionally returns `Left PerasValidationErr` (reject all), rather than `Right` (accept all), so that the unimplemented gate fails closed rather than open.

---

### Proof of Concept

1. Connect to a target node as a peer via the node-to-node protocol with `PerasCertDiffusion` enabled.
2. Observe (via ChainSync) a block hash `H` on a minority fork currently in the target's VolatileDB.
3. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s H }` for any round `r` and slot `s`.
4. Send the certificate via the `PerasCertDiffusion` mini-protocol.
5. `objectDiffusionInbound` → `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
6. The certificate is forwarded to `ChainDB.addPerasCertAsync`.
7. `chainSelSync` finds block `H` in the VolatileDB and calls `chainSelectionForBlock` for it.
8. `constructPreferableCandidates` now computes `wsvTotalWeight` for the fork containing `H` as `blockNo(H) + 15`, which may exceed the honest chain's `blockNo(tip)`, causing the node to switch to the attacker's fork. [1](#0-0) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
