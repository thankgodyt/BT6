### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Chain-Weight Manipulation via Crafted Network Input — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (success) for every certificate it receives. An unprivileged peer can therefore send crafted Peras certificates over the object-diffusion mini-protocol that boost arbitrary blocks on a non-canonical fork. Because the `PerasWeightSnapshot` is built directly from these accepted certificates, the total chain weight used in chain selection (`wsvTotalWeight = blockNo + weightBoost`) is inflated for the adversarial fork, causing an honest node to switch away from the canonical chain.

This is the direct analog of the Ajna M-14 report: just as an attacker depresses the EMA ratio `Debt/(LUP*Collateral)` by adding a crafted entry with extreme collateral and minimal debt, here an attacker inflates the Peras weight metric by injecting crafted certificates that boost blocks on a minority fork, skewing the chain-selection metric in their favour.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

The default instance is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

Every certificate, regardless of content, is accepted and assigned the full `perasWeight` boost.

**Inbound path — `processCerts`:** [2](#0-1) [3](#0-2) 

Certificates received from peers are passed through `validatePerasCert mkPerasParams`. Because that function always returns `Right`, every inbound certificate is stored in the `PerasCertDB`.

**Chain selection triggered by the certificate:** [4](#0-3) 

After a certificate is stored, `chainSelSync` looks up the boosted block in the `VolatileDB` and calls `chainSelectionForBlock`. Chain selection then computes `wsvTotalWeight`: [5](#0-4) 

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

The `wsvWeightBoost` is the sum of all `PerasWeight` values in the snapshot for blocks on the fragment: [6](#0-5) 

A crafted certificate boosting a block on a minority fork inflates that fork's `wsvTotalWeight`, causing `preferCandidate` to return `ShouldSwitch`: [7](#0-6) 

**Secondary effect — immutability boundary shifted:**

`takeVolatileSuffix` uses the same inflated weight to determine which blocks are "immutable" (buried under weight ≥ k): [8](#0-7) 

If the adversary boosts blocks on the current chain, the immutable tip advances prematurely, permanently committing the node to a chain segment it should still be able to roll back. [9](#0-8) 

---

### Impact Explanation

An unprivileged peer can cause an honest node to:

1. **Switch to a non-canonical fork** — by boosting a valid but minority-fork block already present in the node's `VolatileDB`, the adversary makes that fork's `wsvTotalWeight` exceed the canonical chain's, triggering a chain switch.
2. **Prematurely advance the immutable tip** — by boosting blocks on the current chain, the adversary can push the immutable boundary forward, preventing future legitimate rollbacks.

Both outcomes constitute a **High** chain-selection / rollback bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

- The object-diffusion mini-protocol for Peras certificates is reachable from any connected peer; no special privileges are required.
- The boosted block only needs to be present in the node's `VolatileDB`, which is trivially achievable by any peer that has previously served a valid (minority) fork header.
- The attack requires Peras to be enabled. The CHANGELOG notes it is disabled by default, but the code path is fully wired and the `validatePerasCert` stub is the only gate.
- The `TODO` comment at the stub explicitly acknowledges the missing validation, confirming this is a known gap in the production code path, not a test artifact. [10](#0-9) 

---

### Recommendation

Replace the `validatePerasCert` stub with a real implementation that verifies:

1. The certificate's committee membership proof (VRF/BLS signature over the round and boosted block).
2. That the certificate represents a genuine quorum of stake-weighted votes for the claimed round.
3. That the boosted block's slot falls within the correct Peras round window.
4. That no equivocating certificate (same round, different block) already exists in the `PerasCertDB`.

Until real validation is in place, the `processCerts` inbound handler should reject all certificates (or the object-diffusion pool for Peras certificates should not be started) when Peras is not fully deployed. [11](#0-10) 

---

### Proof of Concept

```
Setup: Peras enabled, security parameter k=2160, perasWeight=15.

1. Adversary connects to honest node H and serves a valid minority fork F
   containing block B at slot S (B is now in H's VolatileDB).

2. Adversary sends a PerasCert { pcCertRound = R, pcCertBoostedBlock = B }
   via the object-diffusion protocol.

3. processCerts calls validatePerasCert, which returns Right unconditionally.
   The certificate is stored in PerasCertDB.

4. chainSelSync detects B in VolatileDB and calls chainSelectionForBlock for B.

5. weightedSelectView computes wsvWeightBoost for fork F:
     wsvWeightBoost(F) = perasWeight = 15
     wsvTotalWeight(F) = blockNo(B) + 15

6. If blockNo(B) + 15 > blockNo(tip of canonical chain),
   preferCandidate returns ShouldSwitch and H adopts fork F.

7. Adversary repeats with additional crafted certificates to keep H on F
   or to advance H's immutable tip past the fork point, preventing recovery.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L369-377)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-37)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```
