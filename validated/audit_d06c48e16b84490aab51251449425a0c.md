### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate, bypassing all cryptographic and semantic checks. An unprivileged peer can send a crafted `PerasCert` boosting any arbitrary block. The certificate passes "validation," is stored in the `PerasCertDB`, updates the shared `PerasWeightSnapshot`, and triggers chain selection — potentially causing an honest node to prefer a non-canonical adversarial fork.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` typeclass requires implementors to supply `validatePerasCert`. The universal default instance (covering every `StandardHash blk`) is a stub:

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

No signature, committee membership, round-number, or boosted-block check is performed. Every certificate is accepted.

**Reachable entry path — `processCerts`:**

Inbound certificates from peers are processed by `processCerts` in the object-diffusion layer:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validateCert` is `validatePerasCert mkPerasParams` — the stub — the `(errs, _)` branch is never taken. Every certificate from every peer is unconditionally accepted.

Both production writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) use this stub: [3](#0-2) 

**Shared-state manipulation — `PerasCertDB` and `pcdsLatestCertSeen`:**

`implAddCert` stores the accepted certificate and updates two pieces of shared state:

1. `pcdsCertsByTicket` — feeds `getWeightSnapshot` / `PerasWeightSnapshot`, used directly in chain selection.
2. `pcdsLatestCertSeen` — the "latest certificate seen" counter, the direct analog of the RocketPool deposit-delay counter. It is updated monotonically by round number whenever a new certificate arrives. [4](#0-3) 

**Chain-selection impact — `addPerasCertAsync` → `chainSelSync`:**

After the certificate is stored, `addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  -- Trigger chain selection for the boosted block.
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

Chain selection then calls `preferAnchoredCandidate`, which uses `weightedSelectView` → `weightBoostOfFragment` → `wsvTotalWeight`. The forged boost is included in the total weight comparison:

```haskell
case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
  LT -> ShouldSwitch (Heavier ...)
``` [6](#0-5) 

An attacker who injects a certificate boosting a block on an adversarial fork can make `wsvTotalWeight cand > wsvTotalWeight ours`, causing the honest node to switch to the adversarial chain.

**Analog to M-08:**

| M-08 (RocketPool) | This finding |
|---|---|
| Deposit delay counter — shared mutable state | `pcdsLatestCertSeen` / `PerasWeightSnapshot` — shared mutable state |
| Reset by any user calling `stake()` | Updated by any peer sending a `PerasCert` |
| Blocks `unstake()` for all users | Manipulates chain selection for the whole node |
| Root cause: no per-user isolation of the delay | Root cause: `validatePerasCert` is a no-op stub |

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that certifies any block on any fork. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to inflate the Peras weight of the adversarial fork. Chain selection then prefers the adversarial fork over the honest canonical chain. This is an unauthorized bypass of Peras certificate checks enabling incorrect chain selection — matching the **Critical** impact class (bypass of Peras certificate checks enabling unauthorized certificate acceptance) and the **High** impact class (chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain).

---

### Likelihood Explanation

The Peras protocol is actively being integrated into production code (CHANGELOG entries confirm `PerasCertDB`, `addPerasCertAsync`, and weighted chain selection are all live). The stub is in a production file, not a test or mock. Any peer connected via the object-diffusion mini-protocol can send crafted certificates. No special privileges, keys, or stake are required. Likelihood is high once Peras is enabled on any network.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:

1. Verifies the cryptographic signature(s) on the certificate against the expected committee public keys.
2. Verifies committee membership and stake eligibility for the claimed round.
3. Verifies the round number is consistent with the current chain tip and Peras parameters.
4. Verifies the boosted block point exists and is on a chain that could plausibly be adopted.

Until real validation is in place, the `PerasCert` object-diffusion path should be disabled or gated behind a feature flag that is off by default, preventing untrusted peers from injecting certificates.

---

### Proof of Concept

1. Connect to a node with Peras enabled (or with the `PerasCertDB` / object-diffusion path active).
2. Construct a `PerasCert` with `pcCertBoostedBlock` pointing to a block on an adversarial fork (any valid `Point blk` suffices — no signature is checked).
3. Send the certificate via the object-diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
5. `implAddCert` stores the certificate; `pcdsLatestCertSeen` and `pcdsCertsByTicket` are updated.
6. `addPerasCertAsync` enqueues `ChainSelAddPerasCert`; `chainSelSync` calls `chainSelectionForBlock` for the boosted block.
7. `preferAnchoredCandidate` computes `wsvTotalWeight` including the forged boost; if the adversarial fork's total weight exceeds the honest chain's, the node switches forks.
8. Repeat with incrementing round numbers to keep the adversarial fork permanently preferred.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-201)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-553)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
 where
  tracer :: Tracer m (TraceAddPerasCertEvent blk)
  tracer = TraceAddPerasCertEvent >$< cdbTracer

  certRound :: PerasRoundNo
  certRound = getPerasCertRound cert

  boostedBlock :: Point blk
  boostedBlock = getPerasCertBoostedBlock cert

  -- \| Run a block that can exit early with a result value.
  withEarlyExitId :: ExceptT a (Electric m) a -> Electric m a
  withEarlyExitId = fmap (either id id) . runExceptT

  -- \| Exit early with the given result.
  idExitEarly :: a -> ExceptT a (Electric m) b
  idExitEarly = throwE

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
