### Title
Peras Certificate Validation Bypass via Unconditional `Right` in `validatePerasCert` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance, which is the only instance in scope for all block types including production Cardano blocks, implements `validatePerasCert` as an unconditional `Right`. The `ValidatedPerasCert` wrapper type — intended to be a proof that a certificate has passed cryptographic and structural checks — is applied to any peer-supplied certificate without performing any actual validation. The production inbound certificate processing path (`processCerts`) calls this function as its sole validation gate, so every certificate received from an unprivileged peer is accepted, stored, and used to influence chain selection.

---

### Finding Description

**Root cause.** In `SupportsPeras.hs`, the degenerate instance for all block types implements `validatePerasCert` as:

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

No signature verification, no quorum proof check, no round-number bounds check, and no voter eligibility check is performed. The function wraps any input in `ValidatedPerasCert` unconditionally.

**Attacker-controlled entry path.** The production inbound certificate handler `processCerts` in `PerasCert.hs` calls this function as its only validation step:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validatePerasCert` always returns `Right`, `errs` is always empty and every certificate is accepted. This function is wired into both the `PerasCertDB`-backed writer and the production `ChainDB`-backed writer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

**Downstream effect.** Once a `ValidatedPerasCert` is stored in the `PerasCertDB`, `chainSelSync` in `ChainSel.hs` reads it and, if the boosted block is present in the `VolatileDB`, calls `chainSelectionForBlock` for that block:

```haskell
boostedHdr <-
  lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
    Nothing -> idExitEarly addedCertRes
    Just boostedHdr -> pure boostedHdr
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The Peras weight boost (`vpcCertBoost`) assigned to the fraudulent certificate is `perasWeight mkPerasParams`, which is `PerasWeight 15` — a non-trivial boost that can tip chain selection toward a fork. [5](#0-4) 

**Analog to the external report.** The external report's pattern is: a value is checked/sanitized, but the original unchecked value is used downstream. Here the analog is: `validatePerasCert` is called as the validation gate (the "check"), but its implementation unconditionally wraps the raw peer input in `ValidatedPerasCert` (the "sanitized" type) without performing any actual checks — so the downstream chain-selection code operates on a `ValidatedPerasCert` that is indistinguishable from a legitimately validated one, regardless of the certificate's content.

---

### Impact Explanation

**Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer connected via the Peras certificate miniprotocol can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The certificate passes the validation gate unconditionally, is stored in the `PerasCertDB`, and — if the boosted block is in the `VolatileDB` — triggers chain selection that applies a `PerasWeight 15` boost to that block. This can cause an honest node to prefer a fork over the canonical chain, constituting a chain-selection safety failure driven by a fraudulent Peras certificate.

---

### Likelihood Explanation

**High.** Any peer that can establish a Peras certificate miniprotocol connection can exploit this. No stake, no keys, and no prior knowledge of the chain state beyond knowing a block hash in the target node's `VolatileDB` is required. The code path is unconditional and has no secondary guard.

---

### Recommendation

Implement actual cryptographic and structural validation inside `validatePerasCert` before the Peras certificate miniprotocol is enabled in production. At minimum, the implementation must:

1. Verify the aggregate BLS signature over the claimed voters and the `(roundNo, boostedBlock)` message.
2. Verify each voter's eligibility (committee membership, VRF proof for non-persistent voters).
3. Verify that the total stake of the claimed voters exceeds the quorum threshold.
4. Verify that the certificate's round number is within the valid window relative to the current chain tip.

Until these checks are implemented, the Peras certificate miniprotocol should not be exposed to untrusted peers.

---

### Proof of Concept

1. Attacker connects to a target node via the Peras certificate object-diffusion miniprotocol.
2. Attacker observes (or guesses) a block hash `H` present in the target node's `VolatileDB` on a fork the attacker wants to promote.
3. Attacker sends a batch containing `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slot H }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` — no checks performed.
6. The certificate is stored in the `PerasCertDB` via `addCert`.
7. `chainSelSync` processes the `ChainSelAddPerasCert` message, finds block `H` in the `VolatileDB`, and calls `chainSelectionForBlock` for it.
8. Chain selection now considers the fork containing `H` to have an additional weight of 15, potentially causing the node to switch to the attacker-chosen fork. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
