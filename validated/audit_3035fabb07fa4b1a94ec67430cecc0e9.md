### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a non-validating stub that unconditionally returns `Right` for every certificate it receives. Because this is the only instance in production (it covers all `StandardHash blk`), any unprivileged peer can send a crafted `PerasCert` that passes validation, gets stored in the `PerasCertDB`, updates the `PerasWeightSnapshot`, and triggers chain selection for an arbitrary block — potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a Peras certificate before it is accepted into the node's state. The only concrete instance in the codebase is a degenerate universal instance:

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

This stub is the **only** instance because it is declared as `instance StandardHash blk => BlockSupportsPeras blk`, covering every block type including the production `CardanoBlock`. [2](#0-1) 

This stub is called directly in both production certificate-ingestion paths:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` partitions the batch into valid/invalid using `validateCert`. Because the stub always returns `Right`, the "invalid" partition is always empty and every certificate in the batch is unconditionally added to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Once a certificate is added to the `PerasCertDB`, `ChainSelAddPerasCert` is dispatched. The chain-selection handler adds the certificate's boost to the `PerasWeightSnapshot` and then calls `chainSelectionForBlock` for the boosted block:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  -- Trigger chain selection for the boosted block.
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

Chain selection uses `preferAnchoredCandidate`, which computes `wsvTotalWeight` as `BlockNo + weightBoost`. A crafted certificate with a large `pcCertBoostedBlock` pointing to a block on an adversarial fork can make that fork's `wsvTotalWeight` exceed the honest chain's, causing the node to switch:

```haskell
case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
  LT -> ShouldSwitch (Heavier $ ...)
``` [6](#0-5) 

The Peras weight assigned per certificate is `perasWeight mkPerasParams = PerasWeight 15`, and a single certificate boost of 15 can tip chain selection in favour of a fork that is up to 15 blocks shorter than the honest chain. [7](#0-6) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer can craft a `PerasCert` naming any `(pcCertRound, pcCertBoostedBlock)` pair. Because `validatePerasCert` performs no cryptographic or semantic checks, the certificate is accepted, stored, and its boost is applied to chain selection. The node may then prefer a non-canonical or adversarially-controlled fork over the honest chain, violating the Peras chain-selection invariant. This maps directly to the allowed scope: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

**High.** The Peras certificate mini-protocol (`ObjectDiffusion`) is reachable by any connected peer without authentication. The stub is the only instance in the codebase and is wired into both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`. No feature flag or runtime guard prevents the code path from being exercised whenever Peras is enabled. The only partial mitigation is the `pointSlot boostedBlock < AF.anchorToSlotNo immTip` staleness check, which only discards certificates for already-immutable blocks, not cryptographically invalid ones. [8](#0-7) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:

1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed committee members' keys.
2. That the claimed voters form a valid committee for the given round (VRF-based sortition proof).
3. That the aggregate stake of the committee members exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. That `pcCertRound` is within the valid acceptance window (not expired per `perasCertMaxRounds`).

Until the real implementation is in place, the node should refuse to process inbound certificates from peers (i.e., treat every certificate as invalid) rather than accept all of them unconditionally. The existing `PerasCertInboundException` / disconnect mechanism is already in place and will correctly disconnect peers that send invalid certificates once the validation is real. [9](#0-8) 

---

### Proof of Concept

1. Connect to a Peras-enabled node as an unprivileged peer via the `ObjectDiffusion` mini-protocol.
2. Send a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`.
   - `pcCertBoostedBlock` = the tip of an adversarial fork that is up to 15 blocks shorter than the honest chain.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
4. The certificate is added to `PerasCertDB` via `addCert`.
5. `ChainSelAddPerasCert` is dispatched; `chainSelectionForBlock` is called for the adversarial fork tip.
6. `preferAnchoredCandidate` computes `wsvTotalWeight(adversarial) = blockNo + 15 > wsvTotalWeight(honest) = blockNo`, and the node switches to the adversarial fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L139-145)
```haskell
data PerasCertInboundException
  = forall blk. PerasCertValidationError [PerasValidationErr blk]

deriving instance Show PerasCertInboundException

instance Exception PerasCertInboundException

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
