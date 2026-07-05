### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unprivileged Peer to Manipulate Chain Selection Weight — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in `SupportsPeras.hs` is a stub that always returns `Right` without performing any cryptographic or semantic validation. Because this function is called directly in the production certificate ingestion pipeline (`processCerts` → `makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject crafted `PerasCert` messages that are unconditionally accepted, boosting arbitrary blocks' chain-selection weight and potentially causing an honest node to switch to an adversarial fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for all inbound Peras certificates. The sole production instance of this typeclass is a stub:

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

No signature verification, no quorum check, no voter eligibility check, and no round-number plausibility check is performed. The stub assigns a fixed boost of `perasWeight params` (currently `PerasWeight 15` from `mkPerasParams`) to every certificate regardless of its content. [2](#0-1) 

This stub is called directly in the production inbound-certificate processing path:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- ← always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` partitions results into `([], validatedCerts)` (all valid) or `(errs, _)` (some invalid). Because `validatePerasCert` never returns `Left`, the error branch is unreachable and every certificate from every peer is added to the `PerasCertDB` and forwarded to `addPerasCertAsync`: [4](#0-3) 

Once a certificate is in the `PerasCertDB`, `chainSelSync` triggers chain selection for the boosted block. The `weightedSelectView` computes total weight as `blockNo + weightBoost`, and `preferCandidate` switches to the candidate if its total weight exceeds the current chain's: [5](#0-4) [6](#0-5) 

The `PerasCertDB` deduplicates by round number (one cert per round), but an attacker can send certificates for many distinct rounds, all pointing to the same adversarial block. Each accepted certificate adds `PerasWeight 15` to that block's weight in the `PerasWeightSnapshot`. The snapshot accumulates these boosts via `addToPerasWeightSnapshot`: [7](#0-6) 

---

### Impact Explanation

**Impact: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An adversarial peer can craft `PerasCert` messages for many distinct round numbers, all boosting a block on a minority fork. Because each certificate is accepted without validation, the fork's total weight grows by 15 per injected certificate. A fork that is `n` blocks shorter than the honest chain can be made to appear heavier once `n` certificates are injected (since each certificate contributes weight 15 and each honest block contributes weight 1). On mainnet with `k = 2160`, an adversary can cause a rollback of up to `k` blocks by injecting enough certificates before the honest chain's blocks become immutable.

The `takeVolatileSuffix` function uses `totalWeightOfFragment` (length + boost) to determine the immutability boundary, so artificially inflated weight also shrinks the volatile suffix, potentially causing blocks to be treated as immutable prematurely: [8](#0-7) 

---

### Likelihood Explanation

**Likelihood: Medium** (conditional on Peras being enabled). Peras is currently disabled by default, so this path is not active on mainnet today. However, the production code path is fully wired and the stub is the only implementation. When Peras is enabled (which is the stated goal of the ongoing development), any peer connected via the object-diffusion mini-protocol can immediately exploit this without any special privileges, stake, or key material.

---

### Recommendation

1. **Short term**: Gate the `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` writers behind a Peras-enabled feature flag so the certificate ingestion pipeline is unreachable until `validatePerasCert` is fully implemented.

2. **Long term**: Implement `validatePerasCert` with full cryptographic checks: aggregate BLS signature verification over the round identifier and boosted block hash, voter eligibility proof verification (VRF outputs for non-persistent voters), and quorum threshold enforcement. The concrete certificate type in `Peras.Cert.V1` already defines the necessary fields (`pcSignature`, `pcVoters`) for this validation. [9](#0-8) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to an honest node via the object-diffusion mini-protocol for Peras certificates.
2. Peer sends a batch of `PerasCert` messages, each with a distinct `pcCertRound` (e.g., rounds 0, 1, 2, …, N) and `pcCertBoostedBlock` pointing to a block on an adversarial fork `F`.
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams` returns `Right` for every certificate (no validation performed).
4. Each certificate is timestamped and passed to `ChainDB.addPerasCertAsync`.
5. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block on fork `F`.
6. `weightedSelectView` computes `wsvTotalWeight` for `F` as `blockNo(F_tip) + 15*N`.
7. Once `blockNo(F_tip) + 15*N > blockNo(honest_tip)`, `preferCandidate` returns `ShouldSwitch` and the node adopts fork `F`.

The number of certificates needed to overcome a `d`-block deficit is `ceil(d / 15)`. For a fork 150 blocks behind the honest chain, only 10 crafted certificates suffice. [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```
