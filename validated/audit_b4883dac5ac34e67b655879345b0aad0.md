### Title
`validatePerasCert` Stub Unconditionally Accepts All Peras Certificates, Enabling Chain Selection Manipulation by an Unprivileged Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default instance of `validatePerasCert` in `BlockSupportsPeras` always returns `Right` without performing any cryptographic or semantic validation. Any Peras certificate received from a peer via the diffusion layer is unconditionally accepted and stored in the `PerasCertDB`, where it contributes boost weight to arbitrary blocks during chain selection. A malicious unprivileged peer can inject crafted certificates that boost blocks on non-canonical forks, causing an honest node to prefer and switch to a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

In the default `BlockSupportsPeras` instance, `validatePerasCert` always returns `Right` regardless of the certificate's content:

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

No signature verification, no round-number range check, no boosted-block existence check, and no quorum proof check is performed. The `PerasValidationErr` data type is also a stub with a single constructor `PerasValidationErr` carrying no information. [2](#0-1) 

**Exploit path — `processCerts` feeds peer-supplied certificates directly through the stub:**

`processCerts` in the diffusion layer calls `validateCert` (bound to `validatePerasCert mkPerasParams`) on every inbound certificate. Because the stub always returns `Right`, the `partitionEithers` branch that rejects invalid certificates is never taken, and every certificate is unconditionally forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Both production pool writers — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — pass `validatePerasCert mkPerasParams` as the validator: [4](#0-3) 

**Storage — `implAddCert` also carries a TODO for non-trivial validation:**

The `PerasCertDB` implementation itself notes that validation logic is missing:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert :: ...
``` [5](#0-4) 

The only deduplication check is on `PerasRoundNo`; no check is made that the boosted block in a new certificate for an already-seen round matches the stored one. The first certificate for any round wins unconditionally. [6](#0-5) 

**Chain selection consequence:**

`chainSelSync` in `ChainSel.hs` adds the certificate to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block, using the Peras weight snapshot (which now includes the injected certificate's boost) to compare candidate chains: [7](#0-6) 

The `getWeightSnapshot` function returns all stored certificate boosts, including those from injected certificates, directly influencing which chain the node selects. [8](#0-7) 

**Test precondition acknowledges the equivocation risk but does not enforce it in production:**

The `PerasCertDB` state machine test explicitly avoids equivocating certificates as a precondition, confirming the production code does not enforce this invariant: [9](#0-8) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to a block on a non-canonical fork. Because `validatePerasCert` always returns `Right`, the certificate passes validation, is stored in `PerasCertDB`, and its boost weight is added to the targeted block. `chainSelSync` then triggers chain selection for that block. If the injected boost is sufficient to make the fork's chain score exceed the honest chain's score, the node switches to the non-canonical fork. This is a **High** severity chain selection manipulation: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions.

### Likelihood Explanation

The attack path is directly reachable via the Peras certificate diffusion mini-protocol (`makePerasCertPoolWriterFromChainDB`), which is wired into the production ChainDB. No privileged access, key material, or stake majority is required — only a peer connection. The stub is the active production code path (not gated behind a feature flag in the files examined), making exploitation straightforward once Peras certificate diffusion is live.

### Recommendation

Replace the stub `validatePerasCert` default instance with a real implementation that performs all required checks **before** a certificate is accepted as `ValidatedPerasCert`. At minimum, validation must include:

1. **Cryptographic aggregate signature verification** over the claimed voter set and boosted block.
2. **Quorum check**: the aggregate voting stake must meet the Peras quorum threshold.
3. **Round-number range check**: the certificate's round must be within the valid window relative to the current slot.
4. **Boosted-block existence and ancestry check**: the boosted block must be a known, non-immutable block on a plausible chain.

These checks must be performed inside `processCerts` (or earlier) so that no `ValidatedPerasCert` wrapper is ever constructed for an unverified certificate. The `implAddCert` TODO (issue #120) should be resolved in the same pass.

### Proof of Concept

An attacker peer sends a single `PerasCert` message via the Peras certificate diffusion protocol with:
- `pcCertRound` = any round not yet in the local `PerasCertDB`
- `pcCertBoostedBlock` = the tip of a fork the attacker wants the victim to adopt

**Expected (correct) behavior**: `validatePerasCert` rejects the certificate because no valid aggregate signature or quorum proof is present; `processCerts` throws `PerasCertValidationError`; the certificate is never stored.

**Actual behavior**: `validatePerasCert` returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally; `processCerts` calls `addCert`; `implAddCert` stores the certificate; `chainSelSync` triggers `chainSelectionForBlock` for the attacker-chosen block; the node's chain selection now weights that block with a full Peras boost, potentially causing a fork switch.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-348)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L176-198)
```haskell
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasCertDB/StateMachine.hs (L128-143)
```haskell
  precondition (Model model) = \case
    OpenDB -> not model.open
    action ->
      model.open && case action of
        -- Do not add equivocating certificates.
        AddCert cert -> all p model.certs
         where
          -- We should reject equivocating certificates, that is, certificates
          -- for the same round but boosting different blocks.
          -- So we should enforce: round = round' => boostedBlock = boostedBlock'
          p cert' =
            getPerasCertRound cert /= getPerasCertRound cert'
              || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
        GetWeightSnapshot -> True
        GetLatestCertSeen -> True
        GarbageCollect _slotNo -> True
```
