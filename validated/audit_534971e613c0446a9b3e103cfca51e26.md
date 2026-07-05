### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Chain-Selection Manipulation via Fake Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic verification. Combined with a TOCTOU gap in `processCerts` — where the "already-in-DB" check is atomic but the subsequent validation and insertion are not — an unprivileged peer can inject a crafted `PerasCert` that boosts an adversarial block, causing the receiving node to prefer a non-canonical chain.

---

### Finding Description

**Root cause 1 — stub validation (`SupportsPeras.hs` lines 350–358)**

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

Every `PerasCert` received over the network is unconditionally wrapped in `Right ValidatedPerasCert`. No BLS aggregate-signature check, no committee-membership check, no round-number sanity check is performed. The `ValidatedPerasCert` wrapper is the type-level proof that a certificate is authentic; here it is issued for free to any caller. [1](#0-0) 

**Root cause 2 — TOCTOU in `processCerts` (`PerasCert.hs` lines 164–173)**

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM          -- (A) atomic snapshot
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts  -- (B) non-atomic add
```

Step (A) and step (B) are not in the same STM transaction. Between them, another concurrent call can insert a certificate for the same round. Because `implAddCert` deduplicates only by round number (not by content), whichever certificate wins the race is stored; the other is silently dropped as `PerasCertAlreadyInDB`. An attacker who sends a fake certificate for round R slightly before the legitimate one arrives causes the legitimate certificate to be discarded. [2](#0-1) 

**Root cause 3 — `implAddCert` deduplicates by round number only (`PerasCertDB/Impl.hs` lines 174–198)**

```haskell
implAddCert ... cert = do
  let roundNo = getPerasCertRound cert
  ...
  if Set.member roundNo (pcdsCertIds pcds)
    then pure PerasCertAlreadyInDB
    else do
      ...
      pure AddedPerasCertToDB
```

No equivocation check is performed. The first certificate for a given round wins, regardless of which block it boosts. [3](#0-2) 

**Attack path through `chainSelSync` (`ChainSel.hs` lines 483–531)**

Once the fake certificate is stored, `chainSelSync` reads it, looks up the boosted block in the VolatileDB, and calls `chainSelectionForBlock` for it. Chain selection then assigns the full Peras weight boost (`vpcCertBoost = perasWeight params`) to the adversarial block, potentially making a competing fork heavier than the honest chain. [4](#0-3) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer connected to the Peras object-diffusion mini-protocol can craft a `PerasCert` pointing to any block already present in the node's VolatileDB (e.g., a block on a competing fork). Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to boost that block's chain-selection weight. If the boosted fork becomes heavier than the honest chain, the node switches to it. The `PerasWeightSnapshot` consumed by `preferAnchoredCandidate` during chain selection directly incorporates this injected boost. [5](#0-4) 

---

### Likelihood Explanation

**Medium.** The Peras object-diffusion mini-protocol is implemented and wired into the production `ChainDB` (`addPerasCertAsync`, `makePerasCertPoolWriterFromChainDB`). Any peer that can establish a connection and speak the Peras cert-diffusion sub-protocol can trigger this path. No stake, no keys, and no privileged access are required. The only precondition is that the Peras protocol extension is enabled on the target node. [6](#0-5) 

---

### Recommendation

1. **Replace the stub with real verification.** `validatePerasCert` must verify the BLS aggregate signature against the committee's public keys and confirm that the signers form a quorum, as implemented in `implVerifyCert` for the `EveryoneVotes` scheme. The existing TODO (`cardano-peras/issues/120`) must be resolved before the Peras cert-diffusion path is enabled on any network.

2. **Close the TOCTOU gap in `processCerts`.** Perform the duplicate check, validation, and insertion inside a single STM transaction (mirroring `processVotes`, which already does the check and validation atomically). Alternatively, move the equivocation guard into `implAddCert` so that a certificate for a round already occupied by a different boosted block is rejected rather than silently dropped.

3. **Add an equivocation check to `implAddCert`.** Before storing a new certificate, verify that no certificate for the same round with a different `pcCertBoostedBlock` already exists. The state-machine test already documents this invariant as a precondition; it should be enforced in the production implementation. [7](#0-6) 

---

### Proof of Concept

**Private-testnet sequence (no privileged access required):**

1. Start a node with the Peras cert-diffusion mini-protocol enabled.
2. Ensure the node's VolatileDB contains block `B_adv` on a competing fork (e.g., by diffusing a valid but non-selected block from a legitimate pool).
3. Craft a `PerasCert` with `pcCertRound = R` (any round not yet in the DB) and `pcCertBoostedBlock = point(B_adv)`.
4. Send the crafted certificate to the node via the Peras cert-diffusion sub-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
6. `ChainDB.addPerasCertAsync` enqueues the certificate; `chainSelSync` stores it and calls `chainSelectionForBlock` for `B_adv`.
7. Chain selection now weights `B_adv`'s fork by `perasWeight params` extra; if this exceeds the honest chain's lead, the node switches forks.

To demonstrate the TOCTOU variant: send the fake certificate for round R concurrently with the legitimate certificate for round R. Whichever arrives first is stored; the other is dropped as `PerasCertAlreadyInDB`. If the fake certificate wins the race, the node permanently uses the wrong boosted block for round R. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasCertDB/StateMachine.hs (L132-143)
```haskell
        -- Do not add equivocating certificates.
        AddCert cert -> all p model.certs
         where
          -- We should reject equivocating certificates, that is, certificates
          -- for the same round but boosting different blocks.
          -- So we should enforce: round = round' => boostedBlock = boostedBlock'
          p cert' =
            getPerasCertRound cert /= getPerasCertRound cert'
              || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
        GetWeightSnapshot -> True
        GetLatestCertSeen -> True
        GarbageCollect _slotNo -> True
```
