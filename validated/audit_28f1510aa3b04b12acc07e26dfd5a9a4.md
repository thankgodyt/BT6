### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `processCerts` batch-ingest path in the Peras miniprotocol calls `validatePerasCert` on every certificate received from a peer. The production implementation of `validatePerasCert` is a stub that unconditionally returns `Right` for every input, performing zero cryptographic or structural checks. An unprivileged peer can therefore inject arbitrarily crafted Peras certificates that are accepted, stored, and used to trigger chain selection for boosted blocks — bypassing the entire certificate-authorization layer.

---

### Finding Description

`processCerts` in `PerasCert.hs` is the inbound batch handler for Peras certificates received over the network. It filters out already-known certificates, calls `validateCert` on each remaining one, and — if all pass — adds them to the `PerasCertDB` and triggers chain selection side-effects. [1](#0-0) 

The `validateCert` argument is always wired to `validatePerasCert mkPerasParams`: [2](#0-1) [3](#0-2) 

The sole production implementation of `validatePerasCert` is the catch-all `StandardHash blk` instance, which is explicitly a stub and always returns `Right`: [4](#0-3) 

The comment at the instance head confirms this is intentionally degenerate for now: [5](#0-4) 

No other `BlockSupportsPeras` instance overrides `validatePerasCert` with real cryptographic checks. Every certificate in every inbound batch therefore passes "validation" unconditionally.

The same pattern applies to `validatePerasVote`, which only checks stake-distribution membership and never verifies the vote signature: [6](#0-5) 

---

### Impact Explanation

Once a crafted certificate clears `processCerts`, it is stored in the `PerasCertDB` and the chain-selection engine is invoked for the boosted block: [7](#0-6) 

A Peras certificate carries a `PerasWeight` boost that is factored into the `ChainOrder` comparison. An attacker who can inject certificates for blocks on a minority fork can make an honest node's chain-selection logic prefer that fork over the canonical chain — a direct chain-selection safety failure caused by unauthorized certificate acceptance.

This matches two allowed impact categories:
- **Critical**: Bypass of Peras certificate checks enabling unauthorized certificate acceptance.
- **High**: Chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

The entry path is the ObjectDiffusion miniprotocol, reachable by any peer the node connects to. No special credentials, stake, or key material are required. The attacker only needs to craft a `PerasCert` with a desired `pcCertRound` and `pcCertBoostedBlock` and send it in a batch. Because `validatePerasCert` never fails, the certificate is accepted on the first attempt.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic verification before the ObjectDiffusion miniprotocol is enabled in production. At minimum, the certificate must be checked against the committee's aggregate signature and the claimed quorum of voters must be verified against the current stake distribution. Until a real implementation exists, the inbound certificate handler should reject all certificates rather than accept them unconditionally (i.e., the stub should return `Left` rather than `Right`).

---

### Proof of Concept

1. Connect to a node that has the Peras ObjectDiffusion miniprotocol active.
2. Craft a `PerasCert` with `pcCertRound = R` and `pcCertBoostedBlock = P` where `P` is the tip of a minority fork.
3. Send the certificate via the miniprotocol's `opwAddObjects` path.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is stored in `PerasCertDB` and `chainSelectionForBlock` is triggered for the boosted block.
6. The node's chain-selection logic now assigns extra Peras weight to the minority-fork block, potentially switching to it. [8](#0-7) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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
