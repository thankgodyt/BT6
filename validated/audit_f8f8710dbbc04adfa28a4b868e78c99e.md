### Title
Peras Certificate Validation Bypass: `validatePerasCert` Stub Unconditionally Accepts Any Inbound Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic checks. This stub is wired directly into the live inbound-certificate processing path (`processCerts`) used by both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`. Any unprivileged peer connected via the ObjectDiffusion miniprotocol can send crafted `PerasCert` objects with arbitrary round numbers and boosted block points; every such certificate will be accepted, stored in `PerasCertDB`, and used to trigger chain selection, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation always returns `Right`:**

In `SupportsPeras.hs`, the universal `BlockSupportsPeras` instance (explicitly labelled "degenerate instance for all blks to get things to compile") implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [1](#0-0) 

No signature check, no committee membership check, no round-number range check, no boosted-block validity check — the function wraps the raw, unverified `PerasCert` in a `ValidatedPerasCert` and returns it as valid.

**How the stub is wired into the live inbound path:**

`processCerts` (the function that handles every batch of certificates received from a remote peer) calls `validateCert` — which is bound to `validatePerasCert mkPerasParams` — on every certificate not already in the database:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both production pool writers pass `validatePerasCert mkPerasParams` as the `validateCert` argument: [3](#0-2) 

**How accepted certificates reach chain selection:**

`ChainDB.addPerasCertAsync` enqueues the accepted certificate for `chainSelSync`, which adds it to `PerasCertDB` and, if the boosted block is present in `VolatileDB`, immediately triggers `chainSelectionForBlock` with the certificate's boost weight applied: [4](#0-3) 

The boost weight is `perasWeight mkPerasParams = PerasWeight 15`, a fixed additive weight applied to the boosted block's chain during comparison. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can:

1. Deliver a block to the target node via the normal BlockFetch miniprotocol, placing it in `VolatileDB`.
2. Send a crafted `PerasCert` via the ObjectDiffusion miniprotocol that claims to certify that block for an arbitrary Peras round.
3. Because `validatePerasCert` always returns `Right`, the certificate is stored in `PerasCertDB` without any check.
4. `chainSelSync` detects the boosted block in `VolatileDB` and calls `chainSelectionForBlock`, adding `PerasWeight 15` to the candidate chain's weight.
5. If the boosted candidate chain's weight (including the injected boost) exceeds the current selection, the node switches to the attacker-chosen chain.

This is a **bypass of Peras certificate verification** enabling unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: bypass of Peras voting or certificate checks" impact category.

---

### Likelihood Explanation

**High.** The ObjectDiffusion miniprotocol is a standard peer-to-peer interface; any node that connects to the victim can send `PerasCert` objects. No stake, no keys, and no privileged access are required. The only precondition — that the boosted block be present in the victim's `VolatileDB` — is trivially satisfied by first sending the block via BlockFetch, which is also an unauthenticated peer interface. The stub is in the universal `BlockSupportsPeras` instance that applies to all block types, so there is no block-type-specific escape hatch.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's cryptographic signature against the claimed committee.
- That the round number is within the valid range relative to the current slot.
- That the boosted block point is a known, valid block.
- That the certificate was produced by a quorum of eligible committee members.

Until real validation is in place, the inbound ObjectDiffusion handler for Peras certificates should reject all externally received certificates (e.g., by returning a permanent `Left` from `validatePerasCert`) rather than accepting them unconditionally.

---

### Proof of Concept

Private-testnet sequence:

1. Start a node with the default `mkPerasParams` configuration.
2. Connect an adversarial peer that speaks the ObjectDiffusion miniprotocol.
3. The adversarial peer first sends a block `B` (on a shorter fork) via BlockFetch; the node stores `B` in `VolatileDB`.
4. The adversarial peer then sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = point(B) }` for any round `r` not yet in `PerasCertDB`.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
6. The certificate is stored; `chainSelSync` calls `chainSelectionForBlock` for `B` with `PerasWeight 15` added.
7. If `chain(B) + 15 > weight(current selection)`, the node switches to the fork containing `B`.

No keys, no stake, no special privileges required — only a TCP connection to the victim node. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
