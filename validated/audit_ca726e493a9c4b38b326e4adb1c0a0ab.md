### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Fraudulent Peras Weight Boosts into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. Because this function is the sole validation gate in the production object-diffusion ingest path (`processCerts`), any unprivileged peer can send a crafted `PerasCert` that is accepted without question, stored in the `PerasCertDB`, and used to trigger chain selection — granting an arbitrary weight boost to any block in the VolatileDB.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory validation step before a certificate may be stored or acted upon. The codebase ships a single universal instance (`instance StandardHash blk => BlockSupportsPeras blk`) that is explicitly labelled a "degenerate instance for all blks to get things to compile":

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

This stub is not confined to tests. Both production pool-writer constructors — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — pass `validatePerasCert mkPerasParams` directly as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` relies entirely on `validateCert` returning `Left` to reject a certificate. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is stored:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Once stored, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event. `chainSelSync` then calls `chainSelectionForBlock` for the boosted block, potentially switching the node's preferred chain:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

No check is ever performed on: committee membership, aggregate vote signature, quorum threshold, round validity, or whether the boosted block was actually elected by a legitimate Peras committee.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block hash present in the node's VolatileDB (e.g., a block on a minority fork). The fraudulent certificate passes `validatePerasCert` unconditionally, is stored, and triggers chain selection. The boosted fork now carries additional `perasWeight` in its total weight, which can cause the honest node to prefer the minority fork over the canonical chain. This is a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

The attack requires only a network connection to the target node and knowledge of a block hash in the node's VolatileDB (obtainable via ChainSync). No keys, stake, or operator access are needed. The object-diffusion mini-protocol is reachable from any peer. The stub is the only active implementation of `validatePerasCert` in the codebase.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate vote signature against the claimed committee members.
2. Checks that the signers collectively hold sufficient stake to meet the quorum threshold.
3. Validates that the certificate's round number is within the expected window.
4. Verifies committee membership for each claimed voter against the epoch's stake distribution.

Until real validation is in place, the object-diffusion ingest path for Peras certificates should not be enabled in production builds, or should gate acceptance on a feature flag that is off by default.

---

### Proof of Concept

1. Attacker connects to a target node via the object-diffusion mini-protocol.
2. Attacker observes a block hash `H` on a minority fork via ChainSync.
3. Attacker sends a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = H }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is stored in `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
6. `chainSelSync` looks up block `H` in the VolatileDB, finds it, and calls `chainSelectionForBlock` for it.
7. The minority fork now carries `perasWeight` additional weight; if this exceeds the canonical chain's lead, the node switches to the minority fork. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-137)
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
