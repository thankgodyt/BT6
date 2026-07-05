### Title
Unconditional Certificate Acceptance in `validatePerasCert` Allows Unprivileged Peer to Manipulate Chain Selection via Injected Peras Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural validation. Any unprivileged peer can send crafted certificates that boost arbitrary blocks in the node's `PerasWeightSnapshot`, directly influencing chain selection and causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — the stub validator always returns `Right`:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal `StandardHash blk => BlockSupportsPeras blk` instance implements `validatePerasCert` as:

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

This is the exact structural analog of the reported bug: a guard function that is supposed to exclude invalid items has an **empty exclusion list** — it checks nothing and passes everything through. [1](#0-0) 

**Inbound path — peer-supplied certificates reach this stub:**

`makePerasCertPoolWriterFromChainDB` (and `makePerasCertPoolWriterFromCertDB`) wire this stub directly into `processCerts` as the validation callback:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`processCerts` calls `validateCert` on every certificate received from a peer. Because the stub always returns `Right`, every certificate passes and is forwarded to `addCert` / `ChainDB.addPerasCertAsync`. [2](#0-1) [3](#0-2) 

**Storage — injected certificates enter the weight snapshot:**

`implAddCert` in `PerasCertDB.Impl` stores the certificate unconditionally (it only deduplicates by round number). `implGetWeightSnapshot` then builds a `PerasWeightSnapshot` from all stored certificates, mapping each `pcCertBoostedBlock` to its boost weight. [4](#0-3) [5](#0-4) 

**Chain selection — the poisoned snapshot drives fork choice:**

`chainSelSync` reads `getPerasWeightSnapshot` in every chain-selection cycle and uses the resulting weights to compare candidate chains:

```haskell
<*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

When a certificate arrives via `ChainSelAddPerasCert`, it triggers `chainSelectionForBlock` for the boosted block, potentially switching the node to a fork that carries the attacker-injected weight. [6](#0-5) [7](#0-6) 

`getPerasWeightSnapshot` in `Query` delegates directly to `PerasCertDB.getWeightSnapshot`, so the poisoned snapshot is immediately visible to chain selection. [8](#0-7) 

---

### Impact Explanation

**Severity: High — chain selection manipulation by an unprivileged peer.**

An attacker who can connect to a node (any peer reachable via the object-diffusion mini-protocol) can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block on a minority or adversarial fork.
2. Send it to the target node. `validatePerasCert` accepts it unconditionally.
3. The certificate is stored and its boost weight is added to the `PerasWeightSnapshot`.
4. Chain selection now sees the adversarial fork as heavier than the canonical chain and switches to it.

This allows an unprivileged peer to make an honest node prefer a non-canonical chain, violating the chain-selection security invariant of Ouroboros Peras. The attacker does not need any stake, keys, or privileged access — only a network connection. [9](#0-8) 

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol for Peras certificates is reachable by any peer. The stub is the **only** validation gate between the network and the weight snapshot. No secondary check exists downstream in `processCerts`, `implAddCert`, or `chainSelSync` that would reject a structurally well-formed but cryptographically invalid certificate. The TODO comment and linked issue confirm this is a known gap, not an intentional design. [10](#0-9) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that checks, at minimum:

1. **Quorum proof** — the certificate must carry a valid aggregate signature from a quorum of eligible committee members for the claimed round and boosted block.
2. **Round validity** — `pcCertRound` must correspond to a valid Peras round relative to the current epoch/slot.
3. **Boosted block existence** — `pcCertBoostedBlock` must reference a block that is plausibly on a valid chain (slot within acceptable range).
4. **No duplicate round** — already enforced by `PerasCertDB`, but should also be checked before the DB write.

Until the real implementation is in place, the node should refuse to accept any inbound Peras certificate from peers (return `Left PerasValidationErr` unconditionally) rather than accept all of them. [1](#0-0) 

---

### Proof of Concept

**Setup:** A private two-node testnet with Peras enabled. Node A is the honest node; Node B is the attacker.

**Steps:**

1. Node B connects to Node A via the object-diffusion mini-protocol for Peras certificates.
2. Node B observes that Node A's current chain tip is at block `X` (slot `s`, hash `h`).
3. Node B constructs a fork block `Y` at slot `s+1` extending a different ancestor (or simply references a non-existent hash).
4. Node B sends Node A a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint (s+1) hashOfY }`.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
6. The cert is stored; `PerasWeightSnapshot` now contains a boost for `hashOfY`.
7. `chainSelSync` is triggered via `ChainSelAddPerasCert`; it calls `chainSelectionForBlock` for `hashOfY`.
8. If Node B also sends the corresponding block body for `Y`, Node A's chain selection now weighs the fork as heavier and switches to it.

The attacker needs no stake, no keys, and no privileged access — only a valid peer connection and the ability to craft a `PerasCert` CBOR message. [11](#0-10) [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L374-382)
```haskell
  (succsOf, lookupBlockInfo, curChain, weights) <- atomically $ do
    invalid <- forgetFingerprint <$> readTVar cdbInvalid
    (,,,)
      <$> ( ignoreInvalidSuc cdbVolatileDB invalid
              <$> VolatileDB.filterByPredecessor cdbVolatileDB
          )
      <*> VolatileDB.getBlockInfo cdbVolatileDB
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L344-346)
```haskell
getPerasWeightSnapshot ::
  ChainDbEnv m blk -> STM m (WithFingerprint (PerasWeightSnapshot blk))
getPerasWeightSnapshot CDB{..} = PerasCertDB.getWeightSnapshot cdbPerasCertDB
```
