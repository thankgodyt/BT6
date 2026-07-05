### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Unauthorized Chain-Weight Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate catch-all instance of `BlockSupportsPeras` ships a `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives. Because this instance is the only one compiled into the codebase, any peer on the network can craft an arbitrary Peras certificate, have it accepted without cryptographic or structural verification, and thereby inject an unbounded weight boost into the node's chain-selection logic — potentially causing the node to prefer and adopt an adversarial chain.

---

### Finding Description

`BlockSupportsPeras` declares the method:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only concrete instance in the codebase is the explicitly labelled "degenerate instance for all blks to get things to compile":

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

No signature check, no quorum check, no round-number check, no boosted-block ancestry check — the function simply wraps the raw certificate in a `ValidatedPerasCert` and assigns it the full configured `perasWeight`. The same pattern applies to `validatePerasVote`. [2](#0-1) 

The production call site is the ObjectDiffusion object pool for Peras certificates: [3](#0-2) 

Once a certificate passes `validatePerasCert`, it is inserted into `PerasCertDB` and immediately triggers chain selection for the boosted block: [4](#0-3) 

Chain selection then computes `wsvTotalWeight = blockNo + weightBoostOfFragment`, where `weightBoostOfFragment` sums all boosts for every block on the fragment: [5](#0-4) [6](#0-5) 

A candidate chain is preferred when its `wsvTotalWeight` exceeds the current chain's: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send one or more crafted `PerasCert` objects (each boosting a block on an adversarial fork) via the ObjectDiffusion mini-protocol. Because `validatePerasCert` never rejects anything, each certificate is stored and its `perasWeight` is added to the adversarial fragment's total weight. With enough injected certificates the adversarial fragment's `wsvTotalWeight` exceeds the honest chain's, and `preferAnchoredCandidate` returns `ShouldSwitch`, causing the node to adopt the adversarial chain.

Additionally, `takeVolatileSuffix` uses the same total-weight metric to determine the immutable/volatile boundary: [8](#0-7) 

Injected boosts can therefore also push blocks past the immutability threshold prematurely, preventing the node from ever rolling back to the honest chain even after the attack is detected.

**Impact class**: Critical — bypass of Peras certificate verification that enables unauthorized chain-weight manipulation and potential acceptance of an adversarial chain.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is reachable by any peer the node connects to. No stake, no key material, and no prior relationship is required. The attacker only needs to construct a syntactically valid `PerasCert` record (a round number and a block point), which is trivially serialisable. The attack is therefore low-cost and repeatable.

---

### Recommendation

1. **Implement real validation** in `validatePerasCert`: verify the aggregate BLS signature over `(roundNo, boostedBlock)`, check that the certificate's voter bitmap represents a quorum of the active stake distribution for the relevant epoch, and enforce that `pcCertRound` is within the permissible window relative to the current tip.
2. **Remove the catch-all instance** (`instance StandardHash blk => BlockSupportsPeras blk`) or gate it behind a compile-time flag that is disabled in production builds, so that any block type without a proper implementation fails to compile rather than silently accepting all certificates.
3. **Rate-limit or authenticate** certificate objects at the ObjectDiffusion layer so that peers cannot flood the `PerasCertDB` with spurious boosts even before validation is complete.

---

### Proof of Concept

```
1. Attacker connects to a victim node as a normal peer.
2. Attacker identifies a block B on an adversarial fork that is k blocks
   behind the honest tip (so it is still in the VolatileDB).
3. Attacker constructs N PerasCert values, each with:
     pcCertRound    = <any valid round number>
     pcCertBoostedBlock = blockPoint B
4. Attacker sends all N certificates via the ObjectDiffusion protocol.
5. For each certificate, validatePerasCert returns Right unconditionally.
6. Each certificate is stored in PerasCertDB; implGetWeightSnapshot
   accumulates N * perasWeight for block B.
7. weightBoostOfFragment now returns N * perasWeight for any fragment
   containing B.
8. wsvTotalWeight of the adversarial fragment = blockNo(tip_adv)
   + N * perasWeight, which exceeds the honest chain's blockNo(tip_honest).
9. preferCandidate returns ShouldSwitch; the node adopts the adversarial chain.
10. takeVolatileSuffix may simultaneously bury B under weight k,
    making the switch irreversible.
``` [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-62)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
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
