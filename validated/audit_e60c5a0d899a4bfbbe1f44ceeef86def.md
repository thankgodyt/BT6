### Title
Unconditional Peras Certificate Acceptance Allows Any Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Because this stub is wired directly into the live node-to-node Peras certificate diffusion handler, any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary block by the full Peras weight (15 block-equivalents), causing the receiving node to prefer a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` always succeeds:**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as an unconditional `Right`:

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

No committee membership check, no quorum check, no aggregate signature verification, and no round-number sanity check is performed. The `PerasCert` data type in this instance carries only a round number and a block point — no cryptographic material — so there is nothing to verify even in principle. [2](#0-1) 

**Inbound network path — `processCerts` calls this stub directly:**

`makePerasCertPoolWriterFromChainDB`, the production pool writer used by the node-to-node handler, passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

`processCerts` calls `validateCert` on every new certificate received from a peer, and adds all certificates that return `Right` to the database: [4](#0-3) 

**Live node-to-node handler wires this directly into the network stack:**

The production `hPerasCertDiffusionClient` handler in `NodeToNode.hs` uses `makePerasCertPoolWriterFromChainDB` without any additional validation layer: [5](#0-4) 

**Chain selection is triggered on every accepted certificate:**

Once a certificate passes `validatePerasCert` (which it always does), it is added to the `PerasCertDB` and `ChainDB.addPerasCertAsync` is called, which triggers `chainSelSync` for the boosted block: [6](#0-5) 

The boosted block gains `perasWeight = 15` extra block-equivalents of chain weight, which can cause the node to switch away from the honest canonical chain.

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An attacker who can connect to a node (any peer on the Cardano network) can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block the attacker wants to elevate.
2. Send it over the Peras certificate diffusion miniprotocol.
3. The node accepts it unconditionally, stores it, and triggers chain selection.
4. The targeted block receives a +15 block-weight boost, potentially causing the honest node to prefer a non-canonical adversarial fork over the honest chain.

This directly matches the "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions" impact category.

### Likelihood Explanation

**High.** The attack requires only a standard peer connection — no keys, no stake, no privileged access. The Peras certificate diffusion miniprotocol is enabled in the production node-to-node handler. Any peer that can establish a connection can send a crafted certificate. The stub is the only `BlockSupportsPeras` instance in the codebase and is used unconditionally.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate vote signature against the claimed committee members.
2. Checks that the claimed voters are registered committee members with sufficient combined stake to meet the quorum threshold.
3. Validates that the certificate's round number and boosted block point are consistent with the current ledger state.

Until a real implementation is available, the Peras certificate diffusion miniprotocol should not be enabled in production builds, or inbound certificates should be rejected entirely rather than accepted unconditionally.

### Proof of Concept

A peer connects to a node and sends a `PerasCert` message with:
- `pcCertRound = <any round number>`
- `pcCertBoostedBlock = <point of an adversarial fork block>`

The receiving node's `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15, ... })`. The certificate is stored and `ChainDB.addPerasCertAsync` triggers chain selection. The adversarial block now has 15 extra block-equivalents of weight. If the adversarial fork is within `k` blocks of the honest tip, the node switches to it. [1](#0-0) [7](#0-6) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-328)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
