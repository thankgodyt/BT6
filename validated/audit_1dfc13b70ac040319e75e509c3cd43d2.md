### Title
Peras Certificate Validation Unconditionally Bypassed, Enabling Adversarial Chain Weight Inflation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or semantic validation. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted-block point; the certificate will be stored in the `PerasCertDB` and will inflate the Peras weight of the targeted block, corrupting chain selection.

---

### Finding Description

The `BlockSupportsPeras` instance for all `StandardHash blk` types contains a stub `validatePerasCert` that always returns `Right`:

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

No specialized override exists for `CardanoBlock` or any Shelley-based era; this degenerate instance is the only one in the codebase. [2](#0-1) 

This stub is wired directly into the production network-facing certificate ingestion path. `makePerasCertPoolWriterFromChainDB` constructs an `ObjectPoolWriter` whose `opwAddObjects` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [3](#0-2) 

`processCerts` partitions the validated results and adds all `Right` certificates to the database: [4](#0-3) 

Once a certificate is in the `PerasCertDB`, `chainSelSync` triggers chain selection for the boosted block: [5](#0-4) 

Chain selection then uses `preferAnchoredCandidate`, which computes `weightedSelectView` over the suffixes after the intersection. The `wsvWeightBoost` field is populated by `weightBoostOfFragment`, which sums all boosts from the `PerasWeightSnapshot` for every block on the candidate suffix: [6](#0-5) [7](#0-6) 

The `wsvTotalWeight` is then used as the sole comparator for chain preference: [8](#0-7) [9](#0-8) 

**Analog to M-2:** In M-2, `priceCollateralToUSD` unconditionally subtracts a withdrawal fee that should only be subtracted when live boards exist, causing collateral to be under-valued. Here, `validatePerasCert` unconditionally grants a weight boost (`perasWeight params`) to every certificate regardless of whether it carries a valid quorum signature, a valid round number, or a valid boosted-block reference. The missing condition is the entire cryptographic and semantic validation suite. The result is the inverse distortion: chain weight is over-valued for adversarially crafted certificates, corrupting chain selection rather than collateral pricing.

---

### Impact Explanation

When Peras is enabled (via a non-`NoPerasEnabled` `eraPerasRoundLength`), an unprivileged peer can:

1. Craft a `PerasCert` with `pcCertRound = r` and `pcCertBoostedBlock = adversarialBlockPoint`.
2. Deliver it via the Peras certificate mini-protocol.
3. The node stores it without any validation and adds `perasWeight` (default 15) to the adversarial block's chain weight.
4. Chain selection now prefers the adversarial fork over the honest chain if the weight difference exceeds the honest chain's lead.

This is a **High/Critical chain-selection error**: an unprivileged peer can make an honest node prefer a non-canonical chain by injecting fake certificates, violating the Common Prefix property of Ouroboros Peras.

Additionally, `takeVolatileSuffix` uses `totalWeightOfFragment` to determine the immutable prefix boundary. Inflated weights cause blocks to be treated as immutable prematurely, potentially preventing rollback to the honest chain: [10](#0-9) 

---

### Likelihood Explanation

- **Peras is disabled by default** (`eraPerasRoundLength = HardFork.NoPerasEnabled`), so the attack surface is inactive on current mainnet.
- However, the code is production-ready infrastructure: the `ObjectPoolWriter`, `processCerts`, and `chainSelSync` paths are all wired up and will activate as soon as `eraPerasRoundLength` is set to a non-zero value in any era's `EraParams`.
- No operator compromise or key material is required. Any peer that can open a Peras certificate mini-protocol connection can exploit this.
- The `PerasCert` type is fully serializable and its fields (`pcCertRound`, `pcCertBoostedBlock`) are attacker-controlled. [11](#0-10) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the committee's public keys (as defined in `Ouroboros.Consensus.Peras.Cert.V1`).
2. That `pcCertRound` corresponds to a valid, past Peras round relative to the current chain tip.
3. That `pcCertBoostedBlock` is a known block point within the volatile window.
4. That the certificate's voter set meets the quorum stake threshold (`perasQuorumStakeThreshold`).

Until real validation is implemented, the Peras feature flag (`eraPerasRoundLength`) must not be set to a non-zero value in any production era configuration.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  PerasCert { pcCertRound = 999, pcCertBoostedBlock = adversarialForkTip }
  │  (no valid BLS signature, no quorum, arbitrary round)
  ▼
makePerasCertPoolWriterFromChainDB.opwAddObjects
  │
  ▼
processCerts ... (validatePerasCert mkPerasParams) ...
  │  validatePerasCert always returns Right ValidatedPerasCert { vpcCertBoost = 15 }
  ▼
ChainDB.addPerasCertAsync  →  PerasCertDB stores cert
  │
  ▼
chainSelSync (ChainSelAddPerasCert)
  │  adversarialForkTip not on current chain → triggers chainSelectionForBlock
  ▼
preferAnchoredCandidate cfg weights ours cand
  │  weightBoostOfFragment adds 15 to adversarialForkSuffix
  │  wsvTotalWeight(cand) = blockNo(cand) + 15  >  wsvTotalWeight(ours) = blockNo(ours)
  ▼
ShouldSwitch → node adopts adversarial fork
``` [12](#0-11) [13](#0-12) [14](#0-13)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L104-112)
```haskell
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```
