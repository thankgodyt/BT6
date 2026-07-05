### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inflate Chain-Selection Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing no cryptographic or quorum verification. Because the Peras certificate diffusion pipeline feeds directly into this function, any unprivileged peer can inject crafted certificates that grant arbitrary weight boosts to attacker-chosen blocks, manipulating chain selection on the receiving node.

---

### Finding Description

**Root cause — stub validation that always succeeds**

The catch-all `BlockSupportsPeras` instance in production code contains:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- full configured boost, unconditionally
      }
``` [1](#0-0) 

No BLS aggregate-signature check, no quorum-stake check, and no voter-eligibility check is performed. Every certificate, regardless of content, is wrapped in `ValidatedPerasCert` and assigned the full `perasWeight params` boost.

**Entry path — peer-to-peer certificate diffusion**

Inbound certificates from remote peers are processed by `processCerts`, which calls the injected `validateCert` function (bound to `validatePerasCert mkPerasParams` at the call site):

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` partitions results into valid/invalid; since `validatePerasCert` always returns `Right`, the "invalid" branch is never taken and every certificate is forwarded to `addCert`: [3](#0-2) 

**Weight accumulation — the over-minting analog**

`implAddCert` in `PerasCertDB` deduplicates by round number but does not re-validate. Once stored, `implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certificates. `addToPerasWeightSnapshot` uses `Map.insertWith (<>)`, accumulating weight per boosted block point: [4](#0-3) 

Chain selection then uses `weightedSelectView` / `totalWeightOfFragment` to compare candidate chains, where a higher `wsvWeightBoost` directly causes `preferCandidate` to return `ShouldSwitch`: [5](#0-4) 

**Structural analogy to the over-minting bug**

| DeFi over-minting | Ouroboros analog |
|---|---|
| Synth tokens minted from a calculation without locking collateral | Weight boost granted from a certificate without verifying its BLS signature or quorum |
| `reserveForeign` not deducted → same collateral reused | `validatePerasCert` always `Right` → any crafted cert accepted |
| Tokens backed by nothing | Weight boost backed by no real quorum |
| Attacker drains pool | Attacker steers chain selection |

---

### Impact Explanation

An unprivileged remote peer can send one crafted `PerasCert` per Peras round, each boosting an attacker-controlled block. The receiving node's `PerasWeightSnapshot` accumulates these fraudulent boosts. Because `totalWeightOfFragment` adds `BlockNo + weightBoost`, a short attacker fork with sufficient fraudulent boost can exceed the honest chain's total weight, causing `chainSelectionForBlock` to switch the node's selection to the attacker's fork.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended security assumptions of the Peras protocol. [6](#0-5) 

---

### Likelihood Explanation

The certificate diffusion mini-protocol is reachable by any connected peer. Crafting a syntactically valid `PerasCert` (correct CBOR encoding with any round number, any boosted block point, and a dummy signature) requires no privileged access, no key material, and no stake. The only rate-limiting factor is the per-round deduplication in `PerasCertDB`, which limits the attacker to one fraudulent boost per round — but with multiple rounds available, the cumulative effect is sufficient to flip chain selection.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the BLS aggregate signature over `(roundNo, boostedBlock)` against the declared voter public keys.
2. Checks that the declared voters were eligible (persistent or non-persistent via VRF proof) using the stake distribution from the relevant epoch snapshot.
3. Confirms that the aggregate stake of the declared voters meets the quorum threshold (`stakeAboveThreshold`).

Until a concrete Cardano-era instance is available, the default instance should reject all certificates (`Left PerasValidationErr`) rather than accept all of them, so that the stub cannot be exploited in a deployed node.

---

### Proof of Concept

1. Attacker connects to an honest node as a peer.
2. Attacker identifies block `B` on a minority fork (e.g., a fork 3 blocks behind the honest tip, `BlockNo = N-3`).
3. Attacker crafts `PerasCert { pcRoundNo = R, pcBoostedBlock = B, pcVoters = <any>, pcSignature = <zeroes> }` for rounds `R, R+1, R+2, ...` (one per round, each boosting `B`).
4. Each certificate passes `validatePerasCert` (returns `Right` unconditionally).
5. Each certificate is stored in `PerasCertDB`; `getWeightSnapshot` returns a `PerasWeightSnapshot` with `B` accumulating `perasWeight * numRounds` boost.
6. When `chainSelectionForBlock` evaluates the fork containing `B`, `totalWeightOfFragment` computes `(N-3) + perasWeight * numRounds`, which exceeds the honest tip's `N + 0`.
7. The honest node switches its selection to the attacker's fork. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
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
