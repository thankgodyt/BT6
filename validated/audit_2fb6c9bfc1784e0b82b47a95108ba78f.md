### Title
Peras Certificate Expiry Not Checked on Inbound Peer Path, Allowing Expired Certificates to Influence Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The Peras protocol defines a maximum certificate age of `_A` rounds (`PerasCertMaxRounds`). This expiry bound is enforced when a node decides whether to *include* a certificate in a block it is forging (`needCertRules` → `latestCertSeenIsNotExpired`). However, the same expiry check is entirely absent from the inbound certificate validation path (`processCerts` → `validatePerasCert`), which handles certificates received from remote peers via the object-diffusion miniprotocol. An unprivileged peer can therefore inject an arbitrarily old, expired Peras certificate that the node accepts, stores, and uses to trigger chain selection, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

**Two code paths, one missing check.**

**Path 1 — block-building (expiry check PRESENT):**
`needCertRules` in `Peras/Cert/Inclusion.hs` evaluates the conjunction of three predicates before a node includes a certificate in a block it forges. One of those predicates is `latestCertSeenIsNotExpired`, which enforces `currRoundNo <= _A + latestCertSeenRoundNo`: [1](#0-0) [2](#0-1) 

**Path 2 — inbound cert from peer (expiry check ABSENT):**
`processCerts` is the function that handles every batch of Peras certificates received from a remote peer. It calls the `validateCert` argument, which is always wired to `validatePerasCert mkPerasParams`: [3](#0-2) 

Both production pool writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) pass `validatePerasCert mkPerasParams` as the validator: [4](#0-3) 

**Root cause — `validatePerasCert` is a stub that always returns `Right`:**

The default `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional success, performing zero checks on the certificate's round number, expiry, or any other field: [5](#0-4) 

**Downstream effect — chain selection triggered without expiry guard:**

After `processCerts` stores the accepted certificate, `chainSelSync` is invoked. Its only staleness guard checks whether the boosted block's *slot* is already behind the immutable tip — it does not check whether the certificate's *round number* has expired: [6](#0-5) 

An expired certificate (round `r` where `currRoundNo > _A + r`) therefore passes every gate and is stored in the `PerasCertDB`, updates `latestCertSeen`, and triggers `chainSelectionForBlock` for the boosted block.

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A Peras certificate boosts the weight of the block it certifies. When an expired certificate is accepted and stored, the `PerasWeightSnapshot` used during chain selection includes the illegitimate boost. A peer can craft a certificate pointing to a block on a minority fork, send it to a victim node, and cause that node to switch to the minority fork because the boosted chain now appears heavier. This violates the Peras chain-selection invariant that only non-expired certificates should contribute weight, and can cause durable divergence from the canonical chain.

Additionally, the stored expired certificate becomes the node's `latestCertSeen`, which directly governs the Peras voting rules (VR-1A arrival-time check, VR-1B extension check, VR-2A cooldown check). Poisoning `latestCertSeen` with an expired certificate can suppress legitimate votes or force the node into an incorrect cooldown state.

---

### Likelihood Explanation

Any peer connected via the Peras object-diffusion miniprotocol can send arbitrary `PerasCert` objects. No privileged keys, stake, or operator access are required. The attacker only needs to construct a `PerasCert` with a round number older than `currRoundNo - _A` and a `pcCertBoostedBlock` pointing to a block on a competing fork. The attack is deterministic and requires no brute force.

---

### Recommendation

Add a round-expiry check inside `processCerts` (or inside `validatePerasCert` once it is properly implemented) that rejects any certificate whose round number satisfies `currRoundNo > _A + certRoundNo`. The current round number must be supplied to the validator, mirroring exactly the check already present in `latestCertSeenIsNotExpired`:

```haskell
-- In processCerts or in validatePerasCert:
when (currRoundNo > _A + getPerasCertRound cert) $
  Left (PerasCertExpired (getPerasCertRound cert) currRoundNo)
```

This closes the asymmetry between the block-building path and the inbound-cert path, matching the pattern of the existing `latestCertSeenIsNotExpired` predicate in `needCertRules`.

---

### Proof of Concept

1. Node A is at round `currRoundNo = 100`, with `_A = 10` (so certs from rounds ≤ 89 are expired).
2. Attacker peer constructs `PerasCert { pcCertRound = 5, pcCertBoostedBlock = <minority-fork tip> }`.
3. Attacker sends this cert to Node A via the object-diffusion miniprotocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally. [7](#0-6) 
5. The cert is stored in `PerasCertDB` and `latestCertSeen` is updated.
6. `chainSelSync` checks only `pointSlot boostedBlock < AF.anchorToSlotNo immTip`; since the minority-fork block is recent enough, this guard passes. [8](#0-7) 
7. `chainSelectionForBlock` is called for the minority-fork block, which now carries an illegitimate weight boost, potentially causing Node A to switch to the minority fork.
8. The `latestCertSeenIsNotExpired` check in `needCertRules` would have caught this (`100 > 10 + 5`), but it is never consulted on the inbound path. [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L265-286)
```haskell
-- | latestCertSeenIsNotExpired: the latest certificate seen has not yet expired
-- according to the current round number and the Peras protocol parameters
latestCertSeenIsNotExpired ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
latestCertSeenIsNotExpired
  PerasCertInclusionView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    LatestCertSeenIsNotExpired latestCertSeenRoundNo
      := Bool (currRoundNo <= _A + latestCertSeenRoundNo)
   where
    latestCertSeenRoundNo =
      lcsCertRound latestCertSeen

    _A =
      PerasRoundNo $
        unPerasCertMaxRounds $
          perasCertMaxRounds $
            perasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L318-324)
```haskell
needCertRules ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
