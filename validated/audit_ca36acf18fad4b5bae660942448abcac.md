### Title
`validatePerasCert` Performs No Cryptographic Verification, Allowing Any Peer to Inject Forged Certificates That Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The sole `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. The production inbound-cert miniprotocol handler (`hPerasCertDiffusionClient`) feeds peer-supplied `PerasCert` values directly through this no-op validator and into `ChainDB.addPerasCertAsync`, which triggers chain selection for the boosted block. Any unprivileged peer can therefore inject a forged certificate naming any block in the VolatileDB as its boosted target, granting it a weight bonus of `perasWeight = 15` and potentially causing the honest node to switch to a non-canonical fork.

### Finding Description

**Root cause — `validatePerasCert` is a stub that always succeeds:**

The only `BlockSupportsPeras` instance is the catch-all `instance StandardHash blk => BlockSupportsPeras blk`. Its `validatePerasCert` implementation is:

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

The `PerasCert` data type itself carries no signature field — only a round number and a boosted block point — so there is nothing to verify even if the TODO were addressed:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

**Production inbound path — peer cert → `processCerts` → `addPerasCertAsync`:**

`makePerasCertPoolWriterFromChainDB`, the production writer used by the cert-diffusion miniprotocol, passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on every cert not already in the DB; because `validatePerasCert` always returns `Right`, every cert passes and is forwarded to `addCert`: [4](#0-3) 

This writer is wired into the node-to-node `hPerasCertDiffusionClient` handler, which is reachable by any connecting peer: [5](#0-4) 

**Chain selection consequence — forged cert triggers `chainSelectionForBlock`:**

`chainSelSync` processes the queued cert: it adds it to `PerasCertDB` and, if the boosted block is present in the VolatileDB, immediately calls `chainSelectionForBlock` for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

The weight boost applied is `perasWeight = PerasWeight 15` from `mkPerasParams`: [7](#0-6) 

### Impact Explanation

**Impact: High — chain selection manipulation by an unprivileged peer.**

An attacker who connects as a normal peer can craft a `PerasCert` naming any block hash currently in the target node's VolatileDB as `pcCertBoostedBlock`. Because `validatePerasCert` never rejects anything, the cert is accepted, stored, and used to add 15 weight units to that block's chain. Chain selection then re-evaluates all candidate chains using the boosted weight. If the attacker's chosen block is on a minority fork, the honest node may switch away from the canonical chain to a non-canonical one, violating chain-selection safety assumptions. One forged cert per round is sufficient; the attacker only needs to know a valid block hash (observable from the ChainSync protocol).

### Likelihood Explanation

**Likelihood: High.**

The entry point is the standard Peras cert-diffusion miniprotocol, reachable by any peer without any credentials. The `PerasCert` wire format contains only a round number and a block point — both trivially constructable. No key material, stake, or committee membership is required. The only gate (`getPerasCertIds` deduplication) prevents re-injection of the same round number, but an attacker can use a fresh round number each time.

### Recommendation

1. **Add a signature field to `PerasCert`** and implement `validatePerasCert` to verify the aggregate committee signature against the registered committee keys for the given round, rejecting any cert that does not carry a valid quorum signature.
2. Until the real implementation is ready, **reject all inbound certs at the miniprotocol boundary** (e.g., by returning `Left PerasValidationErr` unconditionally in the stub) rather than accepting them all, so that the unimplemented validation does not silently grant chain-weight boosts to arbitrary peers.
3. Track the open issue (https://github.com/tweag/cardano-peras/issues/120) as a security-blocking item, not merely a correctness TODO.

### Proof of Concept

1. Connect to a target node as a normal peer via the node-to-node protocol.
2. Observe a block hash `H` on a minority fork via ChainSync.
3. Send a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint s H }` over the Peras cert-diffusion miniprotocol for any round `R` not yet in the node's `PerasCertDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = 15}`.
5. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` finds block `H` in the VolatileDB, calls `chainSelectionForBlock` with the boosted weight.
7. If the fork containing `H` now has greater total weight than the current selection, the node switches to it — accepting a non-canonical chain without any legitimate quorum having voted for it. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
