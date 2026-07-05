### Title
Peras Certificate and Vote Validation Completely Bypassed via Degenerate `BlockSupportsPeras` Instance — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance for all block types performs no cryptographic validation of Peras certificates or votes. `validatePerasCert` unconditionally returns `Right` (success), and `validatePerasVote` only checks stake-distribution membership without verifying any cryptographic proof. Any unprivileged peer can inject crafted Peras certificates via the object-diffusion mini-protocol, causing them to be accepted and stored in the `PerasCertDB`, where they directly influence chain selection via weight boosts.

---

### Finding Description

The `BlockSupportsPeras` type class defines the interface for validating Peras certificates and votes. The catch-all production instance is explicitly labelled a "degenerate instance for all blks to get things to compile":

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

This instance provides three stub implementations that perform no real security checks:

**1. `validatePerasCert` always returns `Right`** — any certificate, regardless of cryptographic validity, is unconditionally accepted:

```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

**2. `validatePerasVote` checks only stake-distribution membership** — no signature, VRF proof, or any other cryptographic property is verified:

```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr = Right ...
    | otherwise = Left PerasValidationErr
``` [3](#0-2) 

**3. `getPerasCertInBlock` always returns `Nothing`** — certificates embedded in blocks are never extracted or processed: [4](#0-3) 

These stubs are called directly from the **production inbound-object-diffusion handlers**. `makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams` with a `TODO replace when actual plumbing is in place` comment: [5](#0-4) 

`makePerasVotePoolWriterFromChainDB` similarly calls `validatePerasVote` via the same stub: [6](#0-5) 

The DB-layer implementations carry the same acknowledgement of incompleteness:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert :: ...
``` [7](#0-6) 

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote :: ...
``` [8](#0-7) 

Once a certificate is stored in `PerasCertDB`, `implGetWeightSnapshot` converts it into a `PerasWeightSnapshot` that is consumed by chain selection (`preferAnchoredCandidate` / `switchTo`) to boost the weight of the certified block: [9](#0-8) [10](#0-9) 

---

### Impact Explanation

This is a **bypass of Peras certificate/vote verification**. An unprivileged peer can craft a `PerasCert` naming any block as the boosted target and any round number, send it over the object-diffusion mini-protocol, and have it unconditionally accepted. The accepted certificate is inserted into `PerasCertDB`, updates the `PerasWeightSnapshot`, and causes chain selection to prefer the adversarially-chosen block. This enables an unauthorized chain-selection manipulation: a minority-stake or zero-stake attacker can make an honest node switch to a non-canonical fork by fabricating certificates that boost blocks on that fork, violating Peras safety.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is active whenever the node is running with Peras support compiled in. The attack requires only network connectivity — no stake, no keys, no prior chain knowledge. The `PerasCert` wire type (`pcCertRound` + `pcCertBoostedBlock`) carries no cryptographic proof field, so a valid-looking crafted certificate is trivially constructable. The entire validation gate is a single `Right` return with no checks.

---

### Recommendation

1. Remove the catch-all `instance StandardHash blk => BlockSupportsPeras blk` stub and replace it with per-era implementations that perform full cryptographic validation (signature, VRF proof, committee membership, round-number bounds).
2. Implement the non-trivial validation logic flagged by the TODOs in `implAddCert` and `implAddVote` before enabling Peras on any network.
3. Add a `getPerasCertInBlock` implementation that actually extracts on-chain certificates so the chain-selection weight accounting is consistent with the ledger state.
4. Gate the object-diffusion handlers behind a feature flag that is disabled until validation is complete.

---

### Proof of Concept

```
1. Attacker connects to a target node via the Peras object-diffusion mini-protocol.

2. Attacker constructs a PerasCert:
     PerasCert { pcCertRound    = <any round>
               , pcCertBoostedBlock = <point of adversarial fork block> }

3. Attacker sends the certificate in a batch to the node.

4. processCerts calls validatePerasCert mkPerasParams cert
   → degenerate instance returns Right unconditionally.

5. Certificate is stored in PerasCertDB via implAddCert.

6. implGetWeightSnapshot includes the boosted block in the PerasWeightSnapshot.

7. On the next chain-selection cycle (e.g., triggered by addPerasCertAsync),
   preferAnchoredCandidate uses the inflated weight to prefer the adversarial fork.

8. The node switches to the adversarial chain, violating Peras safety.
``` [11](#0-10) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
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
