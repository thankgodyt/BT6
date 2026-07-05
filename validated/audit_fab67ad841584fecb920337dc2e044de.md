### Title
Stub `validatePerasCert` Always Accepts Any Inbound Peras Certificate, Enabling Unauthorized Chain-Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` type-class declares `validatePerasCert` as the mandatory cryptographic gate for inbound Peras certificates. The sole deployed instance of that class is a degenerate stub that unconditionally returns `Right` — it never performs any cryptographic or semantic check. Because the production inbound pipeline calls this stub directly before storing certificates and triggering chain selection, any unprivileged peer can inject arbitrary fake certificates that boost attacker-chosen blocks, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` is the type class that every block type must satisfy to participate in the Peras protocol. It declares four methods: `validatePerasCert`, `validatePerasVote`, `forgePerasCert`, and `getPerasCertInBlock`. [1](#0-0) 

The only instance in the codebase is a "degenerate" catch-all instance for `StandardHash blk`, explicitly marked as a temporary compilation shim: [2](#0-1) 

Within that instance, `validatePerasCert` is implemented as a stub that always returns `Right` — it assigns the configured `perasWeight` to any certificate it receives, regardless of whether the certificate carries a valid aggregate BLS signature, a legitimate round number, or a boosted block that actually exists: [3](#0-2) 

The production inbound path for Peras certificates is `processCerts` in `PerasCert.hs`. It calls the supplied `validateCert` function on every new certificate received from a peer, and only throws a `PerasCertInboundException` (which disconnects the peer) when that function returns `Left`. Because the stub always returns `Right`, the exception path is unreachable: [4](#0-3) 

Both production pool-writer constructors — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — wire the stub directly as the validator: [5](#0-4) 

The `makePerasCertPoolWriterFromChainDB` variant is the one used in the live node-to-node handler: [6](#0-5) 

After a certificate passes the (non-)validation step it is stored in the `PerasCertDB` and immediately triggers chain selection via `ChainDB.addPerasCertAsync`. Inside `chainSelSync`, the certificate's boosted block receives additional Peras weight, which can flip the outcome of chain selection: [7](#0-6) 

Additionally, `getPerasCertInBlock` is also a stub that always returns `Nothing`, meaning certificates embedded in blocks received from peers are never extracted or validated either: [8](#0-7) 

---

### Impact Explanation

Peras certificates are the mechanism by which the protocol assigns extra weight ("boost") to specific blocks. A node that accepts a fake certificate for an adversarial block will treat that block's chain as heavier than the honest chain, causing it to switch away from the canonical chain. This is a **chain-selection bug** that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain — matching the **High** impact tier: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is active in the production node-to-node handler. Any peer that can establish a connection can send crafted `PerasCert` CBOR messages. No stake, key material, or privileged access is required. The attacker only needs to know the slot and hash of a block they want to boost, both of which are public information from the chain.

---

### Recommendation

1. **Implement `validatePerasCert` properly** in the `BlockSupportsPeras` instance (or in the Cardano-specific instance once the HFC plumbing referenced in issue #73 is complete). At minimum, the implementation must verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregate public key derived from the declared voters, and check that the declared voters collectively hold sufficient stake.

2. **Do not deploy the degenerate stub instance in a Peras-enabled network.** Until a real implementation exists, the Peras certificate diffusion mini-protocol should be disabled or the inbound handler should unconditionally reject all certificates.

3. **Track the concrete validation requirements** in `PerasValidationErr` (currently a single opaque constructor) so that each failure mode — invalid signature, unknown voter, insufficient quorum stake, stale round — can be reported and acted upon individually.

---

### Proof of Concept

An attacker connects to a target node and sends a single `PerasCert` CBOR message over the Peras certificate diffusion channel:

```
PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <hash of adversarial block> }
```

The message is deserialized by the codec, passed to `processCerts`, which calls `validatePerasCert mkPerasParams cert`. The stub returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

`processCerts` sees an empty error list and calls `addCert (WithArrivalTime now validatedCert)`, which invokes `ChainDB.addPerasCertAsync`. `chainSelSync` then runs chain selection for the boosted block, granting it the full configured `perasWeight` boost. If the adversarial fork's boosted-block chain weight now exceeds the honest chain's weight, the node switches to the adversarial fork. [3](#0-2) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L278-316)
```haskell
class
  ( Show (PerasCfg blk)
  , NoThunks (PerasCert blk)
  ) =>
  BlockSupportsPeras blk
  where
  type PerasCfg blk

  data PerasCert blk

  data PerasVote blk

  data PerasValidationErr blk

  data PerasForgeErr blk

  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)

  forgePerasCert ::
    PerasCfg blk ->
    ValidatedPerasVotesWithQuorum blk ->
    Either (PerasForgeErr blk) (ValidatedPerasCert blk)

  -- | Extract a Peras certificate optionally stored in a block.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  getPerasCertInBlock ::
    blk ->
    Maybe (PerasCert blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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
