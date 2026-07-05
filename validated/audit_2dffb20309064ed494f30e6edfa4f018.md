### Title
Hardcoded Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production Peras certificate ingest path calls `validatePerasCert mkPerasParams` with a hardcoded default parameter set and a stub implementation that unconditionally returns `Right` (success) for every certificate it receives. An unprivileged peer can therefore inject arbitrary, cryptographically unsigned Peras certificates via the object-diffusion mini-protocol. Each accepted certificate adds a `PerasWeight 15` boost to an attacker-chosen block, directly influencing chain selection.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate's quorum signatures, committee membership, and protocol-parameter compliance before the certificate is stored and used to boost a block's chain-selection weight.

The only concrete instance of this typeclass is a self-described "degenerate instance for all blks to get things to compile":

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

No field of `cert` is inspected. Every certificate, regardless of origin or content, is accepted and assigned the full `perasWeight` boost.

This stub is wired directly into the production certificate pool writer for the `ChainDB`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← hardcoded stub + hardcoded params
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

The comment on line 87–89 explicitly marks `makePerasCertPoolWriterFromChainDB` as the path for **actual production use**, distinguishing it from the test-only `makePerasCertPoolWriterFromCertDB`. [3](#0-2) 

The hardcoded `mkPerasParams` is a second independent defect: even if a real validator were substituted, it would use tentative default values (e.g. `perasWeight = PerasWeight 15`, `perasQuorumStakeThreshold = 3/4`) rather than the actual on-chain parameters agreed upon by the network. [4](#0-3) 

### Impact Explanation

Once a fake certificate is accepted it is stored in the `PerasCertDB` and its boost is immediately reflected in the `PerasWeightSnapshot` used by chain selection:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

Chain selection then prefers the fragment with the highest `wsvTotalWeight`. An adversary who injects certificates boosting blocks on a minority fork can make that fork appear heavier than the honest chain, causing an honest node to switch to the adversary-controlled chain. This is a direct bypass of the Peras certificate-verification check that is supposed to prevent unauthorized weight boosts.

The `addPerasCertAsync` call inside `makePerasCertPoolWriterFromChainDB` ensures that chain selection is re-run immediately after each accepted certificate. [6](#0-5) 

### Likelihood Explanation

The object-diffusion mini-protocol is a standard peer-to-peer channel. Any node that connects to a victim node can send `PerasCert` objects. The `processCerts` function filters out certificates whose round number is already present in the database, but an attacker can supply certificates for distinct, previously-unseen round numbers without limit. Because `validatePerasCert` never rejects anything, every such certificate is stored and its boost applied. No stake, key material, or privileged access is required.

### Recommendation

1. **Replace the stub** `validatePerasCert` with a real implementation that verifies committee membership, quorum signatures, and round-number validity before accepting a certificate. The linked issue (https://github.com/tweag/cardano-peras/issues/120) tracks this work and should be treated as a security-critical blocker before Peras is enabled on any network.

2. **Thread the actual `PerasParams`** from the node's `TopLevelConfig` into `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` instead of using the hardcoded `mkPerasParams`. This mirrors the fix needed in the Lido report: replace the hardcoded zero/default with the value that reflects the actual protocol state.

3. Until a real validator is in place, consider **disabling inbound certificate acceptance** entirely (or gating it behind the `PerasEnabled` flag) so that the stub cannot be reached from the network.

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to victim node and opens the Peras certificate object-diffusion sub-protocol.
2. Peer sends a `[PerasCert blk]` batch containing a certificate `PerasCert { pcCertRound = R, pcCertBoostedBlock = adversaryBlockPoint }` for any round `R` not yet in the victim's database.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. The stub returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }` unconditionally.
5. The certificate is stored via `ChainDB.addPerasCertAsync`, which triggers `chainSelSync` → `chainSelectionForBlock` for `adversaryBlockPoint`.
6. The `PerasWeightSnapshot` now records `PerasWeight 15` for `adversaryBlockPoint`; any fragment containing that block gains 15 units of weight in `wsvTotalWeight`.
7. Repeating for distinct round numbers accumulates boosts until the adversary's fork outweighs the honest chain, causing the victim to switch. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L87-109)
```haskell
-- | Create a pool writer directly from a 'PerasCertDB'. This is mostly meant
-- for tests against the 'PerasCertDB' in isolation; for actual production use,
-- see 'makePerasCertPoolWriterFromChainDB' which creates a pool writer from the
-- 'ChainDB' with proper handling of chain selection side-effects.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
