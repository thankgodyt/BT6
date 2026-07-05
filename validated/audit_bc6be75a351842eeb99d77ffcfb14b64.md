### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Fraudulent Chain-Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance is explicitly marked as a "degenerate instance … to get things to compile." Its `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Both production inbound-certificate processing paths (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) call this stub directly. An unprivileged peer can therefore inject an arbitrary `PerasCert` — naming any block point and any round number — which will be accepted, stored, and used to boost a chosen block's chain-selection weight, potentially causing the honest node to switch to a non-canonical chain.

### Finding Description

`BlockSupportsPeras` is a type class whose `validatePerasCert` method is supposed to authenticate an inbound Peras certificate before it is stored and acted upon. The sole concrete instance in the codebase is:

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

No signature is verified, no quorum is checked, no committee membership is validated, and no round-number bounds are enforced. The function simply wraps the raw certificate in a `ValidatedPerasCert` and returns it as valid.

This stub is wired directly into both production inbound-certificate pool writers:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls `validateCert` (bound to the stub) on every inbound certificate not already in the database. If all pass — and they always do — each is timestamped and forwarded to `addCert`: [3](#0-2) 

For the `ChainDB`-backed writer, `addCert` resolves to `ChainDB.addPerasCertAsync`, which enqueues the certificate for `chainSelSync`. That function stores the certificate in `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then uses `PerasWeightSnapshot` — built from all stored certificates — to compute `WeightedSelectView.wsvTotalWeight`, which is the sum of block number and accumulated Peras boost weight. A fraudulent certificate with a large boost for an attacker-controlled fork block can tip the comparison in favour of that fork: [5](#0-4) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` (pointing to any block on a competing fork) and an arbitrary `pcCertRound`. Because `validatePerasCert` always returns `Right`, the certificate is stored and its boost (`perasWeight params`) is applied to the targeted block during chain selection. If the boost is large enough relative to the honest chain's length advantage, the node will switch to the attacker's fork — accepting a non-canonical or adversarially constructed chain. This constitutes a **chain-selection safety failure** triggered by a single unauthenticated network message.

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is a public, peer-facing interface. Any connected peer can send a `PerasCert` message. The stub is the only instance in the codebase and is used in both production writers. No operator action or key compromise is required. The only precondition is that the boosted block's slot is newer than the current immutable tip (checked at line 490 of `ChainSel.hs`), which is trivially satisfiable for any recently received block. [6](#0-5) 

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that verifies:
1. The certificate's aggregate signature against the claimed committee members.
2. That the signers collectively hold stake above the quorum threshold (`stakeAboveThreshold`).
3. That the `pcCertRound` is within an acceptable window relative to the current slot.
4. That the `pcCertBoostedBlock` is a known, valid block.

Until the real implementation is in place, the inbound certificate pool writers should not be wired to the production `ChainDB` path, or inbound certificates should be quarantined and not used for chain selection.

### Proof of Concept

1. Connect to a node running with the Peras certificate diffusion mini-protocol enabled.
2. Send a `PerasCert` message with `pcCertBoostedBlock` pointing to the tip of an attacker-controlled fork and `pcCertRound` set to any value not already in the node's `PerasCertDB`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
4. The certificate is stored via `PerasCertDB.addCert` and `addPerasCertAsync` enqueues a chain-selection run.
5. `chainSelectionForBlock` is called for the attacker's fork tip; `weightBoostOfFragment` now includes the fraudulent boost, and if `wsvTotalWeight(fork) > wsvTotalWeight(honest)`, the node switches chains.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
```haskell
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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
