### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Fake Peras Certificates and Trigger Unauthorized Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation in the degenerate `BlockSupportsPeras` instance unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum verification. This function is wired directly into the live `PerasCertDiffusion` miniprotocol handler. Any unprivileged peer can send a crafted `PerasCert` message that passes "validation", is stored in the `PerasCertDB`, and triggers `chainSelectionForBlock` for an attacker-chosen block, potentially causing the victim node to switch to a non-canonical fork boosted by the fake certificate.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate an inbound Peras certificate before it is accepted into the node's state. The degenerate catch-all instance used for all block types implements this gate as:

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

This function accepts every certificate unconditionally — no aggregate BLS signature check, no quorum threshold check, no committee membership check, no round-number plausibility check.

This function is called directly in the production cert diffusion inbound handler via `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

That writer is wired into the live node-to-node protocol stack:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [3](#0-2) 

The `processCerts` function calls `validatePerasCert` on each inbound cert and, if it returns `Right`, immediately passes it to `ChainDB.addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` enqueues the cert for `chainSelSync`, which adds it to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

**Contrast with the vote path:** The vote diffusion handler passes an empty `PerasVoteStakeDistr mempty` as a temporary guard, causing all votes to fail validation today. The cert path has no equivalent guard — `validatePerasCert` always returns `Right` regardless of any runtime state. [6](#0-5) 

The `PerasCertDB.implAddCert` also carries the same "TODO: non-trivial validation logic" note, confirming no secondary validation layer exists: [7](#0-6) 

---

### Impact Explanation

An attacker who can establish a node-to-node connection (any unprivileged peer) can:

1. Craft a `PerasCert` claiming to boost any block hash in the victim's `VolatileDB` (block hashes are observable via `ChainSync`).
2. Send it over the `PerasCertDiffusion` miniprotocol.
3. The cert passes `validatePerasCert` unconditionally and is stored with a full `vpcCertBoost = perasWeight params` weight.
4. `chainSelSync` triggers `chainSelectionForBlock` for the attacker-chosen block, potentially causing the node to switch to a fork that is heavier only because of the fake certificate boost.

This is a **chain selection bug** matching the "High" impact tier: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is registered as a live `InitiatorAndResponder` protocol in the production node-to-node bundle: [8](#0-7) 

Any peer that can complete the node-to-node handshake can immediately send crafted certificates. No stake, no key material, and no prior knowledge beyond publicly observable block hashes is required. The attack is deterministic and requires a single well-formed CBOR-encoded `PerasCert` message.

---

### Recommendation

1. **Immediate:** Add a guard in `makePerasCertPoolWriterFromChainDB` analogous to the empty-stake-distribution guard used for votes, so that all inbound certificates are rejected until real cryptographic validation is implemented.
2. **Correct fix:** Implement `validatePerasCert` to perform full aggregate BLS signature verification, quorum threshold checking, and committee membership verification before returning `Right`, consistent with the `implVerifyCert` logic already present in `Ouroboros.Consensus.Committee.WFALS` and `Ouroboros.Consensus.Committee.EveryoneVotes`.
3. Track this under the existing issue referenced in the TODO comments: `https://github.com/tweag/cardano-peras/issues/120`.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node with Peras enabled and a non-empty `VolatileDB` containing a fork block `B_fork` at point `P`.
2. Connect a malicious peer via the node-to-node protocol.
3. The malicious peer sends a single `PerasCert` message encoding:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = P }
   ```
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}`.
5. `addPerasCertAsync` enqueues the cert; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for `B_fork`.
6. The victim node's chain selection now treats `B_fork`'s chain as heavier by `perasWeight` and switches to it.
7. The victim node has adopted a fork chosen entirely by the attacker, with no legitimate quorum of committee members having voted. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-133)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1263)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-328)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

-- | Add a Peras vote to the VoteDB contained in the ChainDB, and if this
-- results in a new cert being generated, add that cert /asynchronously/ to
-- the ChainDB as well.
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
