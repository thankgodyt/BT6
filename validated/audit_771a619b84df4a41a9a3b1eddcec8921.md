### Title
Unconditional Peras Certificate Acceptance Enables Unauthorized Chain-Selection Override — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production implementation of `validatePerasCert` is a stub that unconditionally returns `Right` (success) for every inbound Peras certificate, performing no cryptographic or structural validation. Because Peras certificates directly influence chain selection by boosting the weight of a block on a competing fork, any unprivileged peer connected via the object-diffusion mini-protocol can forge a certificate for any block in the node's VolatileDB and cause the node to switch away from the canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` instance used for all block types contains the following stub:

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

This function is the sole gate between a raw `PerasCert` received from a peer and a `ValidatedPerasCert` that is trusted by the rest of the system. It performs no signature verification, no committee-membership check, no round-number sanity check, and no quorum check. Every certificate unconditionally passes.

**Inbound path — object diffusion writer:**

When a peer sends a Peras certificate via the object-diffusion mini-protocol, `makePerasCertPoolWriterFromChainDB` is the production writer that processes it. It calls `validatePerasCert mkPerasParams` directly:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then partitions the results of `validateCert <$> certsNotAlreadyInDb`. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain-selection trigger — `chainSelSync`:**

`chainSelSync` processes the accepted certificate. After a slot-age check against the immutable tip, it adds the certificate to the `PerasCertDB` and immediately triggers `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection then uses `preferAnchoredCandidate` with the updated `PerasWeightSnapshot`. If the boosted block is on a competing fork, and the boost (`perasWeight params`) is large enough to make that fork's `wsvTotalWeight` exceed the current chain's, the node switches: [5](#0-4) 

The `WeightedSelectView` comparison adds `wsvBlockNo + wsvWeightBoost` as the total weight: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash present in the target node's VolatileDB. Because `validatePerasCert` never rejects anything, the certificate is accepted, stored, and immediately used to re-run chain selection. If the attacker's fork block receives a boost of `perasWeight params` and that makes the fork's total weight exceed the current chain's total weight, the honest node rolls back to the fork — without any legitimate quorum of committee votes having been cast.

This is a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain** beyond the intended security assumptions of Peras. The rollback depth is bounded by the volatile window (weight ≤ `k`), but within that window the attacker has full control over which fork the node adopts.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a standard node-to-node protocol. Any peer that can establish a connection can send arbitrary `PerasCert` messages. No special privilege, key material, or stake is required. The attacker only needs to know the hash of a block in the target node's VolatileDB (trivially obtained via ChainSync). The attack is therefore reachable by any connected peer whenever Peras is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate committee signature over `(electionId, candidateBlock)`.
2. Checks that the signers form a valid quorum of the committee for the claimed round.
3. Verifies each signer's eligibility (VRF output for non-persistent members, persistent-member list for persistent members).
4. Rejects certificates whose `pcCertRound` is outside the acceptable window relative to the current chain tip.

Until the real implementation is in place, the object-diffusion inbound path for Peras certificates should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.

---

### Proof of Concept

**Setup:** Node A is on chain `Genesis → B1 → B2 → B3` (length 3, no boosts, total weight 3). Attacker controls peer P which has a fork `Genesis → B1 → B2 → F1` (length 3, same weight). Peras is enabled with `perasWeight params = 5`.

**Steps:**
1. Peer P connects to Node A via the object-diffusion mini-protocol.
2. P sends a single `PerasCert { pcCertRound = 1, pcCertBoostedBlock = blockPoint F1 }`.
3. `processCerts` calls `validatePerasCert mkPerasParams` → always `Right ValidatedPerasCert { vpcCertBoost = 5 }`.
4. `chainSelSync` adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for `F1`.
5. `preferAnchoredCandidate` computes: fork suffix `[F1]` has `wsvTotalWeight = 1 + 5 = 6`; current chain suffix `[B3]` has `wsvTotalWeight = 1 + 0 = 1`. Fork is heavier → `ShouldSwitch`.
6. Node A rolls back `B3` and adopts `F1` — a chain switch caused by a forged, unvalidated certificate. [1](#0-0) [2](#0-1) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
