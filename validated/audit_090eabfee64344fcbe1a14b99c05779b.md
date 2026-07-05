### Title
`PerasCertDB` Round-Only Deduplication Key Allows Adversarial Certificate to Permanently Displace Legitimate Certificate, Corrupting Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

`implAddCert` in `PerasCertDB/Impl.hs` deduplicates certificates using only `PerasRoundNo` as the key. A `PerasCert` carries both a round number (`pcCertRound`) and a boosted block (`pcCertBoostedBlock`). Two certificates for the same round but different boosted blocks — equivocating certificates — share the same identifier. Whichever arrives first is permanently stored; the second is silently dropped as `PerasCertAlreadyInDB`. Because the `PerasCertDB` directly feeds chain selection weights and the `getLatestCertSeen` voting precondition, an adversarial peer that races a crafted certificate for round R to arrive before the legitimate one can permanently anchor the wrong boosted block into the node's chain selection state.

---

### Finding Description

`PerasCertDbState` tracks accepted certificates with:

```haskell
pcdsCertIds :: Set PerasRoundNo
``` [1](#0-0) 

The deduplication check in `implAddCert` is:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
``` [2](#0-1) 

The identifier is `roundNo` alone — `pcCertBoostedBlock` is not part of the key. A `PerasCert` is defined as:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound        :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [3](#0-2) 

The same round-only filter is applied upstream in `processCerts`, the inbound handler that receives certificates from network peers:

```haskell
let certsNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
``` [4](#0-3) 

So both the pre-filter and the DB insertion gate on round number only. A certificate for round R boosting block A, once stored, permanently blocks any certificate for round R boosting block B from entering the DB or triggering chain selection.

The `implAddCert` function itself carries an explicit TODO acknowledging that validation logic is absent:

```
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [5](#0-4) 

The stored certificate directly feeds chain selection weights via `implGetWeightSnapshot`:

```haskell
mkPerasWeightSnapshot
  [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
  | cert <- Map.elems (pcdsCertsByTicket pcds)
  ]
``` [6](#0-5) 

And `chainSelSync` exits early without triggering chain selection for the boosted block when `PerasCertAlreadyInDB` is returned:

```haskell
case certRes of
  PerasCertDB.PerasCertAlreadyInDB ->
    idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
  PerasCertDB.AddedPerasCertToDB -> ...
``` [7](#0-6) 

The `getLatestCertSeen` field — which is a precondition for voting in any round after the first — is also set from the first accepted certificate for a round and never updated if a later certificate for the same round arrives:

```haskell
pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
  Nothing -> Just cert
  Just prev
    | getPerasCertRound cert > getPerasCertRound prev -> Just cert
    | otherwise -> Just prev
``` [8](#0-7) 

Because the adversary's certificate is dropped before reaching `implAddCert` (by the `processCerts` pre-filter), `pcdsLatestCertSeen` is never updated to the legitimate certificate.

The network entry point is the `hPerasCertDiffusionClient` handler in `NodeToNode.hs`, which calls `makePerasCertPoolWriterFromChainDB` → `processCerts` → `ChainDB.addPerasCertAsync`: [9](#0-8) [10](#0-9) 

The state machine test explicitly acknowledges the equivocation scenario but only prevents it via a test precondition, not in production code:

```haskell
-- Do not add equivocating certificates.
-- We should reject equivocating certificates, that is, certificates
-- for the same round but boosting different blocks.
p cert' =
  getPerasCertRound cert /= getPerasCertRound cert'
    || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
``` [11](#0-10) 

---

### Impact Explanation

An adversarial peer that delivers a certificate for round R boosting a minority or adversary-controlled block A before the honest network delivers the legitimate certificate for round R boosting canonical block B causes:

1. The adversary's certificate is stored; `pcdsCertIds` records round R as seen.
2. The legitimate certificate is silently dropped by `processCerts` (round R already in `alreadyInDb`) and never reaches `implAddCert` or `chainSelSync`.
3. `getWeightSnapshot` returns Peras boost weight for block A, not block B.
4. `chainSelSync` applies the Peras weight to block A's chain, potentially making it preferred over the canonical chain containing block B.
5. `getLatestCertSeen` returns the adversary's certificate, which is the precondition for voting in subsequent rounds — the node's own voting behavior in future rounds is anchored to the wrong block.

This is a **High** impact chain selection bug: an unprivileged peer can make an honest node permanently prefer a non-canonical chain by racing a crafted certificate.

---

### Likelihood Explanation

The attack requires only that the adversary's certificate for round R arrives at the victim node before the legitimate certificate. Because the `processCerts` pre-filter is a simple `Set.member` check on round number with no cryptographic or stake-weight validation (the TODO comment confirms validation is not yet implemented), the adversary does not need a stake majority to forge a certificate that passes the current filter. Any peer connected via the `hPerasCertDiffusionClient` mini-protocol can submit a certificate. Network timing manipulation (e.g., eclipse attack, selective delay of honest peers) makes the race reliably winnable.

---

### Recommendation

Replace the `Set PerasRoundNo` deduplication key with a key that includes the boosted block, i.e., `Set (PerasRoundNo, Point blk)`, so that equivocating certificates are distinguished rather than collapsed. Additionally, when a certificate for a round already in the DB arrives with a *different* boosted block, the node should treat it as an equivocation and either reject it with a peer penalty or apply a policy (e.g., keep the one with higher stake weight). The `processCerts` pre-filter at line 166 must be updated consistently. The missing validation logic (tracked in issue #120) should be implemented before the Peras certificate diffusion path is enabled on mainnet.

---

### Proof of Concept

```
Private testnet with two honest nodes H1, H2 and one adversarial node A.

Round R begins. The canonical quorum votes for block B.

1. A constructs PerasCert { pcCertRound = R, pcCertBoostedBlock = blockA }
   where blockA is on a minority fork. Because implAddCert has no validation
   (TODO #120), this certificate passes processCerts unchanged.

2. A sends this certificate to H1 via hPerasCertDiffusionClient before H2
   can relay the legitimate certificate for block B.

3. H1 receives A's certificate:
   - processCerts: getPerasCertRound cert = R, not in alreadyInDb → passes filter
   - validatePerasCert: passes (no-op under current TODO stub)
   - implAddCert: Set.member R pcdsCertIds = False → stored; pcdsCertIds = {R}

4. H2 relays the legitimate certificate { pcCertRound = R, pcCertBoostedBlock = blockB }:
   - processCerts: getPerasCertRound cert = R, R ∈ alreadyInDb → filtered out
   - Certificate never reaches implAddCert or chainSelSync.

5. H1's getWeightSnapshot returns boost weight for blockA.
   chainSelSync for blockA triggers chainSelectionForBlock, potentially
   switching H1's selection to the minority fork.

6. H1's getLatestCertSeen = adversary's cert (blockA), satisfying the
   voting precondition for round R+1 with the wrong boosted block.
``` [12](#0-11) [13](#0-12) [14](#0-13)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L51-52)
```haskell
  { pcdsCertIds :: !(Set PerasRoundNo)
  -- ^ The round numbers of all certificates currently in the db.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-201)
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
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L209-213)
```haskell
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L188-193)
```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
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
