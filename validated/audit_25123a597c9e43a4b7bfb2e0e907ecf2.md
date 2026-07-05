### Title
Peras Certificate Validation Unconditionally Returns `Right`, Enabling Unauthorized Chain-Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance — the only instance currently wired into the production Peras certificate diffusion path — implements `validatePerasCert` as a stub that unconditionally returns `Right` without performing any cryptographic or semantic checks. An unprivileged peer can therefore send a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block in the volatile DB, have it accepted as "validated," and trigger chain selection for that block with an artificial weight boost, potentially causing an honest node to prefer a non-canonical fork.

### Finding Description

**Root cause — stub validation that always succeeds:**

The degenerate `BlockSupportsPeras` instance, explicitly marked as a placeholder, implements `validatePerasCert` as:

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

This is the **universal instance** (`instance StandardHash blk => BlockSupportsPeras blk`) and is therefore the instance resolved for every concrete block type in the system. [1](#0-0) 

**Production inbound path — `processCerts` calls this stub:**

Inbound certificates received from peers are processed by `processCerts`, which calls the injected `validateCert` function. In both production writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`), the injected validator is `validatePerasCert mkPerasParams` — the stub above. [2](#0-1) 

`processCerts` partitions the results: if all certs pass (i.e., `partitionEithers` yields an empty error list), every cert is timestamped and added to the database. Because the stub always returns `Right`, the error list is always empty. [3](#0-2) 

**Chain selection is triggered for the boosted block:**

Once a cert is added to the `PerasCertDB`, `addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. The background `chainSelSync` handler then calls `chainSelectionForBlock` for the block named in `pcCertBoostedBlock`, re-evaluating whether to switch to the fork containing that block with the additional Peras weight boost applied. [4](#0-3) 

The weight snapshot used during chain selection is derived directly from all certs in the `PerasCertDB`, including the injected one: [5](#0-4) 

**Analog to the external report's vulnerability class:**

The external report describes a state-update guard (`block.timestamp > lastExchangeRateUpdate`) that prevents interest from accruing within the same block, enabling zero-cost loans. The analog here is a validation guard (`validatePerasCert`) that is supposed to enforce the cryptographic cost of producing a valid certificate (quorum of committee signatures, VRF proofs, correct round/block binding) but instead always passes — enabling zero-cost certificate injection. In both cases, a check that should enforce a real cost is bypassed due to an incomplete/stub implementation.

### Impact Explanation

An unprivileged peer can:

1. Craft a `PerasCert blk` with `pcCertRound` set to any round number not yet in the DB, and `pcCertBoostedBlock` pointing to any block hash in the volatile DB (e.g., the tip of a minority fork).
2. Send it over the Peras cert diffusion mini-protocol.
3. The receiving node accepts it unconditionally, adds it to the `PerasCertDB`, and triggers `chainSelectionForBlock` for the boosted block.
4. The boosted block's fork now carries an artificial `perasWeight` advantage in chain selection.
5. If the artificial boost is sufficient to make the minority fork heavier than the current selection, the honest node switches to the attacker-controlled fork.

This is a **Critical** bypass of Peras certificate validation enabling unauthorized certificate acceptance, and a **High** chain-selection bug enabling an unprivileged peer to make an honest node prefer a non-canonical chain.

### Likelihood Explanation

The entry point is the standard Peras cert diffusion mini-protocol, reachable by any peer that can establish a connection to the node. No privileged keys, stake, or operator access are required. The attacker only needs to know a block hash present in the target node's volatile DB (obtainable via the ChainSync mini-protocol). The stub is the only instance in the codebase and is unconditional — there is no fallback or feature flag that would activate real validation.

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic validation before the Peras cert diffusion path is enabled in production. At minimum, the validation must verify:

1. The certificate's aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the committee's aggregate verification key.
2. That the signing committee members were legitimately elected (VRF proofs for each member).
3. That the total stake of the signing committee exceeds the quorum threshold.
4. That `pcCertRound` and `pcCertBoostedBlock` are consistent with the current chain state (round is not in the future beyond a bound, boosted block is a real block on a known chain).

Until real validation is in place, the Peras cert inbound diffusion path should be disabled or gated behind a feature flag that is off by default.

### Proof of Concept

```
1. Attacker connects to an honest node via the Peras cert diffusion mini-protocol.

2. Attacker learns a block hash H on a minority fork F via ChainSync.

3. Attacker sends a PerasCert { pcCertRound = R, pcCertBoostedBlock = H }
   where R is any round number not yet in the node's PerasCertDB.

4. processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })

5. The cert is added to PerasCertDB; addPerasCertAsync enqueues ChainSelAddPerasCert.

6. chainSelSync calls chainSelectionForBlock for H with the artificial weight boost.

7. If perasWeight params is large enough relative to the current chain's length advantage,
   the node switches its selection to fork F.

Expected: certificate rejected with a cryptographic validation error.
Actual:   certificate accepted; chain selection re-run for the attacker-chosen block.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
