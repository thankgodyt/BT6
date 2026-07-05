### Title
Peras Certificate Validation Bypass Allows Arbitrary Chain Weight Inflation via Crafted Network Certificates - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types unconditionally accepts every inbound Peras certificate as valid, without performing any cryptographic or semantic checks. This is the direct analog of the IdleProvider bug: just as `tokenPrice()` returns a price figure that omits fees and thereby overstates the balance used for rebalancing decisions, `validatePerasCert` returns `Right` (success) for every certificate regardless of content, thereby overstating the chain weight used for chain-selection decisions. An unprivileged peer can exploit this to inject crafted certificates that artificially boost the weight of any block, potentially causing an honest node to prefer a non-canonical adversarial chain.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve a certificate before it enters the `PerasCertDB` and influences chain selection. The universal degenerate instance, which is the only instance currently compiled for all block types, implements this gate as an unconditional pass-through:

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

This instance is the only one in scope for production block types (the comment explicitly marks it as a "degenerate instance for all blks to get things to compile"): [2](#0-1) 

The production network ingestion path for Peras certificates, `makePerasCertPoolWriterFromChainDB`, calls this stub directly:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` then adds every certificate that passes this non-check to the `PerasCertDB`: [4](#0-3) 

The `PerasCertDB` exposes a `getWeightSnapshot` that feeds directly into chain selection: [5](#0-4) 

Chain selection computes `wsvTotalWeight` as `BlockNo + weightBoost` and switches to a candidate chain whenever its total weight exceeds the current chain's: [6](#0-5) 

`weightBoostOfFragment` sums the boost of every point on the candidate fragment using the snapshot: [7](#0-6) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `pcCertBoostedBlock` (e.g., the tip of an adversarial fork) and any `pcCertRound`. Because `validatePerasCert` always returns `Right`, the certificate is stored in the `PerasCertDB` and its boost is included in the weight snapshot. Chain selection then computes a higher `wsvTotalWeight` for the adversarial fork than for the honest chain, and the node switches to it. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of Peras.

The structural parallel to the IdleProvider bug is exact:

| | IdleProvider | Ouroboros Peras |
|---|---|---|
| Incomplete function | `tokenPrice()` (omits fees) | `validatePerasCert` (omits all checks) |
| Overstated value | Balance of underlying | Chain weight of candidate |
| Downstream decision | Vault rebalancing | Chain selection |
| Attacker input | Idle pool profit | Crafted `PerasCert` over network |

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a live network-facing endpoint. Any peer that can connect to the node can submit a batch of `PerasCert` objects. The `processCerts` function is the only validation barrier, and it delegates entirely to `validatePerasCert`, which is the stub. No stake, key material, or privileged access is required. The attack is deterministic and requires only knowledge of the target block's `Point` and a valid CBOR encoding of `PerasCert`.

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that verifies:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the committee's aggregate verification key.
2. That the voter bitmap in `pcVoters` represents a quorum of the committee for the given round.
3. That `pcCertRound` is within the acceptable window (not too old, not in the future).
4. That `pcCertBoostedBlock` refers to a block that satisfies the minimum age (`PerasBlockMinSlots`) requirement.

Until the real implementation is in place, the node should refuse to process inbound Peras certificates from the network (i.e., `processCerts` should reject all certificates rather than accept all of them). [1](#0-0) 

### Proof of Concept

1. Attacker connects to a victim node via the Peras certificate ObjectDiffusion mini-protocol.
2. Attacker observes that the honest chain tip is at `BlockPoint slotN hashH` with `BlockNo N`.
3. Attacker has an adversarial fork whose tip is at `BlockPoint slotA hashA` with `BlockNo N-1` (one block shorter).
4. Attacker crafts `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slotA hashA }` with an arbitrary `R` not yet in the victim's `PerasCertDB`.
5. Attacker sends this certificate to the victim. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
6. The certificate is stored. `getWeightSnapshot` now returns a snapshot with `BlockPoint slotA hashA ↦ perasWeight`.
7. When chain selection next runs, `weightBoostOfFragment` adds `perasWeight` to the adversarial fork's `wsvWeightBoost`. If `perasWeight` ≥ 1, the adversarial fork's `wsvTotalWeight` equals or exceeds the honest chain's, and `preferCandidate` returns `ShouldSwitch`.
8. The victim node switches to the adversarial fork. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

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
