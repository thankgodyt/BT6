### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Arbitrary Weight-Boost Injection into Chain Selection — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` method is a no-op stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or semantic verification. Because the Peras certificate diffusion pipeline calls this stub on every inbound certificate from any peer, an unprivileged remote peer can inject arbitrarily crafted `PerasCert` messages. Each accepted certificate is inserted into the `PerasCertDB` and immediately reflected in the `PerasWeightSnapshot`. That snapshot is the sole input to `weightedSelectView` / `wsvTotalWeight`, which drives chain selection, and to `takeVolatileSuffix`, which determines the immutability boundary. The result is a direct analog of the DeFi "donation" attack: an attacker injects external data to skew a weighted calculation, causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional certificate acceptance** [1](#0-0) 

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

This is the only `BlockSupportsPeras` instance in the codebase (declared as a "degenerate instance for all blks to get things to compile"). [2](#0-1)  Every call to `validatePerasCert` returns `Right`, regardless of the certificate's round number, boosted block point, voter set, or aggregate signature.

**Inbound pipeline — peer certificates reach the stub without any prior gate**

The network-facing `processCerts` function calls `validatePerasCert` directly on every certificate received from a peer that is not already in the database: [3](#0-2) 

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    (validatePerasCert mkPerasParams)   -- ← always Right
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [4](#0-3) 

Any certificate that passes the round-number deduplication check is timestamped and forwarded to `addPerasCertAsync`.

**Weight snapshot update — injected boost enters chain selection**

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

The `PerasCertDB.getWeightSnapshot` then reflects the new boost. Chain selection reads this snapshot via `getPerasWeightSnapshot`: [6](#0-5) 

```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
```

**Chain selection uses the injected weight**

`weightedSelectView` computes `wsvTotalWeight = blockNo + weightBoost` and `preferCandidate` switches to any candidate whose total weight exceeds the current chain's: [7](#0-6) 

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch ...
```

**Immutability boundary also affected**

`takeVolatileSuffix` uses `totalWeightOfFragment` (block count + boost) to determine which blocks are buried under weight `k` and therefore immutable: [8](#0-7) 

Injecting boosts onto blocks in the volatile window can push the immutable tip forward prematurely, permanently committing blocks that honest nodes have not yet agreed upon.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block point in the volatile window as the boosted block. Because `validatePerasCert` always succeeds, the certificate is accepted, the `PerasWeightSnapshot` is updated, and chain selection is re-run. If the attacker's fork has fewer blocks than the honest chain but the injected boost makes its `wsvTotalWeight` larger, the node switches to the attacker's fork — accepting a non-canonical, potentially adversarially-constructed chain. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of Peras.

Additionally, by injecting boosts onto blocks already on the current chain, the attacker can advance the immutable tip faster than warranted, causing the node to permanently commit to a chain prefix that other honest nodes have not yet finalized — a **High** ChainDB/LedgerDB rollback/immutability invariant violation.

---

### Likelihood Explanation

The attack requires only a network connection to the target node. No stake, no keys, no admin access. The attacker sends one `PerasCert` per round number (the deduplication check prevents re-injection for the same round). With many rounds available, the attacker can inject boosts for many blocks. The Peras certificate diffusion mini-protocol is a standard peer-to-peer channel, so any peer reachable by the node is a potential attacker. Likelihood is **High** for any deployment running this codebase with Peras enabled.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with full cryptographic verification before any certificate is admitted to the `PerasCertDB` or used to update the `PerasWeightSnapshot`. Specifically:

1. Verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed voter set (as already implemented for the `WFALS` committee in `EveryoneVotes.hs` lines 301–337).
2. Verify that each claimed voter seat index is within bounds and has positive stake in the epoch's stake distribution snapshot.
3. Verify that the total voting stake of the claimed voters exceeds the quorum threshold.
4. Reject any certificate whose `pcCertBoostedBlock` does not correspond to a known valid block header.

Until full validation is in place, the `processCerts` inbound handler should refuse all externally-received certificates rather than silently accepting them.

---

### Proof of Concept

```
Precondition:
  - Honest node N has current chain C of length L with no Peras boosts.
    wsvTotalWeight(C) = L.
  - Attacker A has a fork F of length L-1 (one block shorter).
    wsvTotalWeight(F) = L-1 < L  →  N would not switch.

Attack:
  1. A connects to N as a peer via the Peras cert diffusion mini-protocol.
  2. A sends PerasCert { pcCertRound = r, pcCertBoostedBlock = tip(F) }
     with any content (no valid signature required).
  3. processCerts calls validatePerasCert → Right (always).
  4. Certificate is added to PerasCertDB; PerasWeightSnapshot gains
     boost B = perasWeight params for tip(F).
  5. chainSelSync triggers chainSelectionForBlock for tip(F).
  6. weightedSelectView computes:
       wsvTotalWeight(F') = (L-1) + B
     If B >= 2, then wsvTotalWeight(F') >= L = wsvTotalWeight(C).
  7. preferCandidate returns ShouldSwitch → N adopts fork F.

Result: N has switched to the attacker's shorter, non-canonical fork.
        The honest chain C is abandoned.
``` [1](#0-0) [4](#0-3) [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-322)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
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
