### Title
Peras Certificate Validation Bypass via Unconditional `Right` Stub Allows Unprivileged Peer to Corrupt Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Both production pool-writer paths (`makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB`) pass this stub as the validation function to `processCerts`, which is the inbound handler for peer-supplied Peras certificates. Any unprivileged peer can therefore inject arbitrary crafted `PerasCert` objects that are accepted without verification, stored in the `PerasCertDB`, and used to artificially boost the chain weight of any attacker-chosen block, corrupting chain selection.

---

### Finding Description

**Step 1 – The stub validator always succeeds.**

The `BlockSupportsPeras` instance for all `blk` defines `validatePerasCert` as:

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

This is not a test helper — it is the only instance of `BlockSupportsPeras` in the codebase and is used in production. No signature, quorum, committee membership, round validity, or boosted-block existence check is performed.

**Step 2 – Both production pool writers pass this stub to the inbound handler.**

`makePerasCertPoolWriterFromChainDB` (the production path wired to the `ChainDB`) passes `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

The same stub is used in `makePerasCertPoolWriterFromCertDB`: [3](#0-2) 

**Step 3 – `processCerts` accepts every cert that passes `validateCert`.**

`processCerts` filters out already-known round numbers, then calls `validateCert` on the remainder. If all pass (which they always do), each cert is timestamped and forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

**Step 4 – Accepted certs are stored and directly influence chain selection.**

`implAddCert` stores the cert in `pcdsCertsByTicket` and updates `pcdsLatestCertSeen` without any further validation: [5](#0-4) 

`implGetWeightSnapshot` then builds a `PerasWeightSnapshot` mapping each cert's `pcCertBoostedBlock` to its `vpcCertBoost` (= `perasWeight mkPerasParams` = 15): [6](#0-5) 

`chainSelSync` uses this snapshot to trigger `chainSelectionForBlock` for the boosted block, directly re-running chain selection with the artificial weight applied: [7](#0-6) 

**Step 5 – The attacker controls both fields of `PerasCert`.**

A `PerasCert blk` contains only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`, both fully attacker-controlled: [8](#0-7) 

The attacker can craft a cert with any `pcCertBoostedBlock` pointing to a block already in the node's VolatileDB. The only guard in `chainSelSync` is that the boosted block's slot must not be older than the immutable tip — a block in the volatile suffix trivially satisfies this.

---

### Impact Explanation

An unprivileged peer can inject one crafted `PerasCert` per Peras round (the deduplication check is per `PerasRoundNo`). Each accepted cert adds `perasWeight = 15` to the chain weight of the attacker-chosen block. `totalWeightOfFragment` sums block count plus all Peras boosts along a fragment; a chain boosted by enough injected certs will be preferred over the honest canonical chain. This constitutes a **chain selection corruption** that causes the node to adopt a non-canonical chain without any stake majority or key compromise by the attacker.

Additionally, `getLatestCertSeen` is updated to the highest-round injected cert, which is a precondition for the node's own voting logic — an attacker can manipulate this to suppress or redirect the node's votes.

**Impact category: High** — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or adversarially-boosted chain.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is reachable by any connected peer without authentication. The `PerasCert` type is trivially constructable (two fields: a round number and a block point). The attacker only needs to know a valid block hash in the target node's volatile suffix, which is observable via the ChainSync protocol. No keys, stake, or privileged access are required. The vulnerability is present in every node running this codebase with Peras enabled.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras feature is enabled on any network. At minimum, this must verify: (a) the aggregate BLS/committee signature over the certificate, (b) that the claimed voters form a valid quorum per the stake distribution, (c) that `pcCertRound` corresponds to a valid past round, and (d) that `pcCertBoostedBlock` refers to a block that actually exists and was produced in the correct slot range for that round.

2. **Remove the unconditional `Right` stub** from the `BlockSupportsPeras` instance. The TODO at `https://github.com/tweag/cardano-peras/issues/120` must be resolved before this code path is reachable on any production or public testnet node.

3. **Add a guard in `processCerts`** that rejects any cert whose `pcCertBoostedBlock` is not present in the local ChainDB, preventing chain-selection side-effects from phantom block references.

---

### Proof of Concept

**Attacker preconditions:** peer connection to the target node; knowledge of one block hash `H` in the node's volatile suffix (obtainable via ChainSync).

**Steps:**

1. Observe block hash `H` at slot `S` via ChainSync.
2. For each Peras round `r` from 1 to `N`, craft:
   ```
   PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint S H }
   ```
3. Send all `N` certs to the target node via the ObjectDiffusion inbound channel.
4. Each cert passes `validatePerasCert` (returns `Right` unconditionally).
5. Each cert is stored in `PerasCertDB`; `implGetWeightSnapshot` now maps `BlockPoint S H` to `PerasWeight (15 * N)`.
6. `chainSelSync` triggers `chainSelectionForBlock` for `H` with the inflated weight.
7. The node's chain selection now treats any chain containing `H` as having `15 * N` additional weight, causing it to be preferred over honest competing chains that lack this artificial boost.

**Expected outcome:** the node switches to or locks onto the attacker-boosted chain, diverging from the canonical chain selected by honest peers that have not received the crafted certs.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
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
