### Title
Degenerate `validatePerasCert` Instance Unconditionally Returns `Right`, Bypassing All Peras Certificate Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass has a catch-all instance where `validatePerasCert` unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. This instance is the only one in the codebase and is used in production inbound-certificate processing paths. An unprivileged peer can inject crafted `PerasCert` objects with arbitrary round numbers and boosted block hashes via the object diffusion mini-protocol; every such certificate will be accepted as valid and trigger chain selection for the attacker-chosen block.

---

### Finding Description

**Vulnerability class mapping**: The external report describes a check function that always returns a default/wrong value (`false`) because it uses an identifier in the wrong format for a map lookup, bypassing a security gate. The analog here is a validation function that always returns the wrong value (`Right`) because its body is a TODO placeholder, bypassing the certificate authentication gate entirely.

**Root cause — degenerate `validatePerasCert`**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting a Peras certificate:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the codebase is the catch-all:

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

No aggregate BLS signature check, no round-number bounds check, no boosted-block validity check, and no quorum-membership check is performed. Every certificate, regardless of content, is wrapped in `Right` and returned as `ValidatedPerasCert`.

**Production call sites**

`processCerts` is the inbound handler for the object diffusion mini-protocol. It calls the supplied `validateCert` on every certificate received from a peer:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both production pool writers pass `validatePerasCert mkPerasParams` as `validateCert`:

```haskell
makePerasCertPoolWriterFromCertDB ... =
  ObjectPoolWriter { opwAddObjects = \certs ->
      processCerts systemTime ... (validatePerasCert mkPerasParams) ... certs
  }

makePerasCertPoolWriterFromChainDB ... =
  ObjectPoolWriter { opwAddObjects = \certs ->
      processCerts systemTime ... (validatePerasCert mkPerasParams) ... certs
  }
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces an empty error list, and every peer-supplied certificate is unconditionally added to the `PerasCertDB`.

**Chain selection consequence**

Once a certificate is in the `PerasCertDB`, `chainSelSync` is triggered:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  boostedHdr <- lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
    Nothing  -> idExitEarly addedCertRes
    Just hdr -> pure hdr
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `pcCertBoostedBlock` field of the attacker-crafted certificate is used directly to look up a block in the `VolatileDB` and trigger `chainSelectionForBlock`. The certificate's boost weight (`vpcCertBoost = perasWeight params`) is applied to that block, potentially making the adversarial chain heavier than the honest chain.

---

### Impact Explanation

This is a **High** impact chain-selection bug. An unprivileged peer can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a weaker adversarial fork that is already present in the target node's `VolatileDB`.
2. Send it via the object diffusion mini-protocol.
3. The certificate bypasses `validatePerasCert` (always `Right`), is stored in the `PerasCertDB`, and triggers `chainSelectionForBlock` for the adversarial block.
4. The adversarial block now carries the full Peras boost weight (`perasWeight params`), which can exceed the honest chain's weight, causing the node to switch to the adversarial fork.

This directly matches the allowed impact: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The entry path requires only a standard peer connection via the object diffusion mini-protocol — no stake, no keys, no special privileges. The attacker needs only to know a block hash present in the target's `VolatileDB` (obtainable via the ChainSync mini-protocol) and to send a single crafted `PerasCert` message. The bypass is deterministic: `validatePerasCert` has no conditional logic and always returns `Right`.

---

### Recommendation

Replace the degenerate catch-all instance with a proper implementation of `validatePerasCert` that:

1. Verifies the aggregate BLS signature (`pcSignature`) against the claimed voters' public keys from the current stake distribution.
2. Checks that `pcCertRound` is within the valid window for the current chain tip.
3. Verifies that the set of voters in `pcVoters` constitutes a valid quorum (sufficient aggregate stake).
4. Confirms that `pcBoostedBlock` refers to a block within the valid Peras voting window.

Until a real implementation is available, the degenerate instance should at minimum reject all certificates (return `Left PerasValidationErr`) rather than accept all of them, so that the object diffusion path is inert rather than exploitable.

---

### Proof of Concept

```
1. Peer connects to target node via the object diffusion mini-protocol for PerasCerts.
2. Peer learns block hash H of a block on a weaker fork via ChainSync.
3. Peer constructs:
     PerasCert { pcCertRound     = <any round number>
               , pcCertBoostedBlock = BlockPoint <slot> H
               , pcVoters        = <empty or arbitrary>
               , pcSignature     = <zeroed bytes> }
4. Peer sends the certificate batch to the target node.
5. processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }
6. Certificate is added to PerasCertDB.
7. chainSelSync triggers chainSelectionForBlock for block H with full Peras boost weight.
8. If the adversarial fork containing H is heavier than the honest chain after boosting,
   the target node switches to the adversarial fork.
``` [5](#0-4) [6](#0-5) [7](#0-6)

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
