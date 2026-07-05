### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function contains no actual validation logic and unconditionally returns `Right` for every inbound certificate. This is the direct analog to the external report's missing `_requireIsNotSanctioned` check before `_transfer()`: a required gating check is absent before a state-changing operation. When Peras is enabled, any unprivileged peer can submit a crafted `PerasCert` that passes "validation," is stored in the `PerasCertDB`, and artificially boosts the weight of any block in the VolatileDB, causing chain selection to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gatekeeper before a certificate is accepted into the system. The production default instance, which applies to all block types until era-specific instances are wired in, implements this function as:

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

This unconditionally wraps any input `PerasCert` in `Right ValidatedPerasCert`, skipping all checks: committee membership, cryptographic signature, round validity, boosted-block existence, and era eligibility. [1](#0-0) 

The network-facing ingest path in `processCerts` calls this function for every certificate received from a peer:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validateCert` is bound to `validatePerasCert mkPerasParams`, the left branch (errors) is never reached. Every certificate passes, is timestamped, and is forwarded to `addCert`. [2](#0-1) 

The accepted certificate is then stored in `PerasCertDB` via `implAddCert`, which updates the `PerasWeightSnapshot` used by chain selection: [3](#0-2) 

`chainSelSync` then uses this snapshot to trigger `chainSelectionForBlock` for the boosted block, potentially switching the node to a non-canonical fork: [4](#0-3) 

Chain selection compares fragments using `WeightedSelectView`, where `wsvWeightBoost` is drawn directly from the `PerasWeightSnapshot` populated by the unvalidated certificate: [5](#0-4) 

---

### Impact Explanation

When Peras is enabled via feature flags (`rnFeatureFlags`), an unprivileged peer can submit a `PerasCert` pointing to any block in the VolatileDB. The certificate is accepted without any check, its boost weight (`perasWeight params`) is added to the target block's `PerasWeightSnapshot` entry, and chain selection re-runs. If the boosted block is on a fork, the node may switch to that fork, constituting a chain selection manipulation attack that causes an honest node to prefer a non-canonical chain beyond the intended security assumptions.

This matches the **High** impact category: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

Peras is disabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference`). However, the feature flag infrastructure exists and nodes that opt in are immediately exposed. The attack requires only network connectivity and knowledge of a block hash in the target node's VolatileDB — both trivially obtainable from the ChainSync mini-protocol. No keys, stake, or privileged access are required.

---

### Recommendation

Implement actual cryptographic and semantic validation inside `validatePerasCert` before the Peras feature flag is enabled in any production or pre-production environment. Required checks include:

1. **Committee membership**: verify the certificate's signers are eligible committee members for the claimed round.
2. **Aggregate signature verification**: verify the cryptographic aggregate signature over the election ID and candidate block.
3. **Round validity**: verify the certificate's round number is within the valid window relative to the current chain tip.
4. **Boosted block existence and era eligibility**: verify the boosted block point corresponds to a block in a Peras-enabled era.

The `validatePerasCert` function in `BlockSupportsPeras.hs` must not return `Right` unconditionally. The existing `Committee.Class` infrastructure (`verifyCert`) provides the correct pattern to follow. [6](#0-5) 

---

### Proof of Concept

1. Enable Peras on a target node via `rnFeatureFlags`.
2. Connect as an unprivileged peer via the Peras certificate mini-protocol.
3. Obtain the hash of a block on a non-canonical fork from the node's ChainSync candidate fragment.
4. Craft a `PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <fork block point> }` and send it.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. The certificate is stored in `PerasCertDB`; `implGetWeightSnapshot` now returns a snapshot with the fork block boosted.
7. `chainSelSync` calls `chainSelectionForBlock` for the boosted block; `preferAnchoredCandidate` now computes a higher `wsvTotalWeight` for the fork fragment.
8. The node switches to the non-canonical fork. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L116-123)
```haskell
  -- | Verify a certificate attesting the winner of a given election
  verifyCert ::
    VotingCommittee crypto committee ->
    Cert crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (NE [EligibilityWitness crypto committee])

```
