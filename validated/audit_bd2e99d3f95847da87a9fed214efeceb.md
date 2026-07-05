### Title
Peras Certificate Validation Stub Allows Unprivileged Peer to Inject Arbitrary Certificates into Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation for all block types is a stub that unconditionally returns `Right`, accepting every inbound Peras certificate without any cryptographic or protocol-level check. Because the object-diffusion inbound path calls this stub before storing certificates in `PerasCertDB`, any connected peer can inject arbitrary certificates. Once stored, those certificates permanently influence chain selection via the weight snapshot, and `PerasCertDB` provides no mechanism to expunge them on the basis of invalidity — only slot-age garbage collection can remove them. This is the direct structural analog of the Perennial "funds locked in factory" bug: value is pushed into a component that has no path to reject or undo it.

---

### Finding Description

**Root cause — stub validation always succeeds**

The sole `BlockSupportsPeras` instance, covering every block type, contains:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

Every certificate, regardless of content, is wrapped in `Right` and returned as `ValidatedPerasCert`.

**Inbound path — peer-supplied certificates reach the stub**

`processCerts` in the object-pool writer for Peras certificates calls this stub directly:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← stub, always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` filters out already-known round numbers, then calls `validateCert` on the remainder. Because the stub always returns `Right`, every novel certificate passes: [3](#0-2) 

**Storage — accepted certificates are permanently indexed**

`implAddCert` (also carrying its own TODO for "non-trivial validation logic") stores the certificate in `pcdsCertsByTicket` and updates `pcdsLatestCertSeen`: [4](#0-3) 

**No invalidity-based removal path**

`PerasCertDB` exposes only one removal operation — `garbageCollect slotNo` — which removes certificates whose boosted block's slot is strictly older than `slotNo`. There is no API to remove a certificate because it is cryptographically invalid or protocol-violating: [5](#0-4) 

The GC implementation confirms this: only slot-age filtering is applied, and `pcdsLatestCertSeen` is never cleared: [6](#0-5) 

**Chain-selection impact**

`implGetWeightSnapshot` builds the Peras weight snapshot directly from `pcdsCertsByTicket`. Every injected certificate contributes a weight boost (`perasWeight params = 15`) to its nominated block: [7](#0-6) 

`chainSelSync` uses this snapshot when processing `ChainSelAddPerasCert` messages, potentially switching the node to a fork that carries the injected boost: [8](#0-7) 

**Structural analog to the Perennial bug**

| Perennial | Ouroboros Consensus |
|---|---|
| `fund()` calls `claimFee()`, tokens sent to `MarketFactory` | Peer sends cert → `processCerts` → stub accepts → stored in `PerasCertDB` |
| `MarketFactory` has no `withdraw()` | `PerasCertDB` has no invalidity-based removal |
| Protocol fees permanently locked | Invalid cert permanently boosts attacker-chosen block |

---

### Impact Explanation

An unprivileged peer connected via the Peras object-diffusion mini-protocol can craft a certificate nominating any block hash and any round number. Because `validatePerasCert` always succeeds, the certificate is stored and immediately contributes a weight boost of `perasWeight` (currently 15) to the attacker's chosen block. The node's chain-selection logic will then prefer any candidate chain that includes that block over an equally-long honest chain without a boost. The injected certificate cannot be evicted until the boosted block's slot falls below the immutable tip, giving the attacker a sustained window to steer the node toward a non-canonical chain. This satisfies the "Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance" and "High — chain selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

---

### Likelihood Explanation

Any peer that can establish an object-diffusion connection can exploit this. No stake, no keys, and no prior knowledge of the chain are required — only the ability to construct a `PerasCert` message with an arbitrary round number and block point, which is a plain serialisable data type. The attack is repeatable and requires no brute force.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the certificate's BLS aggregate signature, committee membership, and round-number bounds before returning `Right`. Until that implementation exists, the inbound path in `processCerts` should reject all certificates rather than accept them unconditionally.
2. Add an invalidity-based removal operation to `PerasCertDB` (analogous to the `withdraw` function recommended in the Perennial report) so that certificates accepted under a broken validator can be purged without waiting for slot-age GC.
3. Enforce the `implAddCert` TODO validation before the Peras object-diffusion protocol is enabled on any network that connects to untrusted peers.

---

### Proof of Concept

1. Connect to a node via the Peras certificate object-diffusion mini-protocol.
2. Send a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <hash of attacker-controlled block>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = 15}`.
4. `addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message.
5. `chainSelSync` adds the cert to `PerasCertDB` and triggers chain selection for the boosted block.
6. `getWeightSnapshot` now returns a snapshot that adds 15 weight units to the attacker's block.
7. Any candidate chain containing that block is now preferred over an equally-long honest chain, causing the node to switch forks.
8. The certificate remains in `PerasCertDB` until the boosted block's slot is older than the immutable tip; no API call can remove it earlier.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-174)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L257-275)
```haskell
  gc :: PerasCertDbState blk -> PerasCertDbState blk
  gc
    PerasCertDbState
      { pcdsCertsByTicket
      , pcdsLastTicketNo
      , pcdsLatestCertSeen
      } =
      let pcdsCertsByTicket' =
            Map.filter
              (\cert -> pointSlot (getPerasCertBoostedBlock cert) >= NotOrigin slotNo)
              pcdsCertsByTicket
          pcdsCertIds' =
            Set.fromList (getPerasCertRound <$> Map.elems pcdsCertsByTicket')
       in PerasCertDbState
            { pcdsCertIds = pcdsCertIds'
            , pcdsCertsByTicket = pcdsCertsByTicket'
            , pcdsLastTicketNo = pcdsLastTicketNo
            , pcdsLatestCertSeen = pcdsLatestCertSeen
            }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L73-83)
```haskell
  , garbageCollect ::
      SlotNo ->
      STM m (m ())
  -- ^ Garbage-collect certificates whose target slot is strictly smaller
  -- than the given slot number.
  -- The STM transaction clears the relevant state from the in-memory index, and
  -- the resulting 'm' action performs tracing and might perform side-effects in
  -- implementations with on-disk storage.
  --
  -- NOTE: Use the `join . atomically` pattern to consume its output.
  }
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
