### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Arbitrary Peras Weight Injection into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate without performing any cryptographic or semantic check. An unprivileged peer can send a crafted `PerasCert` via the ObjectDiffusion mini-protocol that claims to boost any arbitrary block. The receiving node accepts it, inflates the `PerasWeightSnapshot` for that block, and re-runs chain selection using the manipulated weight — directly analogous to the Curve spot-price manipulation where an attacker injects a false price to distort a critical on-chain calculation.

---

### Finding Description

**Root cause — stub validation always succeeds**

The default `BlockSupportsPeras blk` instance (valid for any `StandardHash blk`) implements `validatePerasCert` as:

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

No signature check, no committee membership check, no round-number sanity check, and no verification that the claimed `pcCertBoostedBlock` was ever actually voted on. Every certificate is stamped `ValidatedPerasCert` with the full configured `perasWeight`.

**Inbound path — production code calls this stub**

`makePerasCertPoolWriterFromChainDB`, the production writer used by the ObjectDiffusion mini-protocol, calls `validatePerasCert mkPerasParams` on every batch of certificates received from a peer:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [2](#0-1) 

`processCerts` partitions the batch into valid/invalid using this function; because the stub never returns `Left`, the "invalid" bucket is always empty and every certificate is forwarded to `addCert`: [3](#0-2) 

**Weight injection — the accepted certificate mutates chain selection**

Once accepted, the certificate is stored in `PerasCertDB`. `chainSelSync` then reads the updated `PerasWeightSnapshot` and re-runs `chainSelectionForBlock` for the boosted block: [4](#0-3) 

`preferAnchoredCandidate` uses `weightedSelectView`, which sums `wsvBlockNo` and `wsvWeightBoost` into `wsvTotalWeight`. A candidate fork whose boosted block now carries an attacker-injected weight can exceed the honest chain's total weight and trigger a chain switch: [5](#0-4) 

**Secondary impact — immutability boundary shifts**

`getCurrentChainLike` calls `takeVolatileSuffix` with the live weight snapshot to determine which blocks are "immutable" (beyond rollback weight `k`). An attacker who injects a certificate boosting a block on the *current* chain shortens the volatile suffix, causing the node to treat more blocks as immutable and refuse legitimate rollbacks: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

When Peras is enabled, an attacker controlling a single peer can:

1. Identify a valid but shorter fork in the VolatileDB.
2. Send a crafted `PerasCert` claiming to boost the tip of that fork.
3. The stub accepts it; the fork's `wsvTotalWeight` is inflated by `perasWeight params`.
4. `preferAnchoredCandidate` now returns `ShouldSwitch` for the fork; the node abandons the honest chain.

Alternatively, by boosting a block on the current chain, the attacker can shrink the volatile suffix and prevent the node from ever rolling back to a longer honest chain, violating the Common Prefix property.

---

### Likelihood Explanation

**Medium.** Peras is currently an experimental feature (disabled by default). However:
- The ObjectDiffusion mini-protocol and `processCerts` code are production-grade and already wired into `ChainDB`.
- No privilege is required beyond a standard peer connection.
- The stub is explicitly acknowledged as incomplete (multiple `TODO` comments referencing issue #120), meaning the gap between the current state and a secure implementation is known and unresolved.
- Once Peras is enabled on any network (testnet or mainnet), the attack is trivially executable by any connected peer.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the known committee public keys (as already modelled in `Ouroboros.Consensus.Peras.Cert.V1`).
2. Checks that the round number is within an acceptable window relative to the current chain tip.
3. Verifies that the boosted block hash is a known, valid block.
4. Rejects equivocating certificates (same round, different block) before they reach `PerasCertDB`.

Until a real implementation exists, the ObjectDiffusion inbound path for Peras certificates should be gated behind the Peras feature flag so that the stub is never reachable on a live node.

---

### Proof of Concept

**Setup**: Peras enabled; honest node has current chain `A → B → C` (length 3); attacker has a fork `A → B → D` (length 2, normally rejected).

1. Attacker connects as a peer and sends one `PerasCert { pcCertRound = 1, pcCertBoostedBlock = blockPoint D }`.
2. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` (e.g., weight 15 on mainnet).
3. `chainSelSync` adds the cert to `PerasCertDB`; `PerasWeightSnapshot` now maps `blockPoint D → PerasWeight 15`.
4. `chainSelectionForBlock` is triggered for `D`; `weightedSelectView` computes:
   - Honest suffix `[B, C]`: `wsvTotalWeight = PerasWeight 2` (2 blocks, 0 boost).
   - Attacker suffix `[B, D]`: `wsvTotalWeight = PerasWeight 17` (2 blocks + 15 boost).
5. `preferCandidate` returns `ShouldSwitch (Heavier ...)`; the node rolls back to `B` and adopts `D`.

The attacker has caused the node to abandon the honest chain using a single unauthenticated network message. [1](#0-0) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
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
