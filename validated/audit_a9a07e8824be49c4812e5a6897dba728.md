### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or structural checks whatsoever. The production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB` → `processCerts`) calls this stub as its sole validation gate before adding peer-supplied certificates to the `PerasCertDB` and triggering chain selection. Any unprivileged peer can therefore inject arbitrary `PerasCert` values that will be accepted, stored, and used to apply Peras weight boosts to attacker-chosen blocks, causing the honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — stub validation that always succeeds:**

The universal default instance at `SupportsPeras.hs:320` covers every block type:

```haskell
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

No signature verification, no committee membership check, no quorum proof, no round-number sanity check — every certificate is unconditionally wrapped in `ValidatedPerasCert` and returned as `Right`.

**Attacker-controlled entry path — the production inbound writer:**

`makePerasCertPoolWriterFromChainDB` is the production writer wired into the Peras object-diffusion mini-protocol. Its `opwAddObjects` field calls `processCerts` with `validatePerasCert mkPerasParams` as the sole validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert` into errors and successes. Because `validatePerasCert` never produces an error, every cert in the batch is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection consequence:**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: if the boosted block is on a candidate fork, the cert's `vpcCertBoost` weight is added to that fork's `PerasWeightSnapshot`, and chain selection is re-run. If the attacker's chosen fork now outweighs the honest chain, the node switches to it: [4](#0-3) 

The `vpcCertBoost` assigned to every accepted cert equals `perasWeight params` — the full configured Peras weight boost — regardless of whether any real quorum was ever reached.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and any round number. Because `validatePerasCert` always returns `Right`, the cert passes the only validation gate, is stored in the `PerasCertDB`, and its weight boost is applied during chain selection. If the attacker targets a block on a fork that is otherwise shorter than the honest chain, the injected boost can make that fork preferred, causing the honest node to roll back and adopt the attacker's chain. This is a **bypass of Peras certificate verification** enabling unauthorized certificate acceptance and chain-selection manipulation by any unprivileged peer — matching the Critical/High impact categories (Peras certificate check bypass; chain-selection bug allowing a non-canonical chain to be preferred).

### Likelihood Explanation

The Peras object-diffusion mini-protocol is reachable by any peer that can establish a node-to-node connection — no stake, no keys, no prior relationship required. The attacker needs only to send a well-formed CBOR-encoded `PerasCert` message. The stub is the **only** validation step; there is no secondary check in `chainSelSync` or `PerasCertDB.implAddCert` that would reject a structurally valid but cryptographically fraudulent certificate. [5](#0-4) 

### Recommendation

Replace the stub `validatePerasCert` default implementation with a real check that verifies: (1) the certificate's aggregate signature against the claimed committee members' public keys, (2) that the signers constitute a valid quorum under the current stake distribution, and (3) that the round number and boosted block point are within the expected window. Until the full Peras cryptographic plumbing is in place, the inbound cert pipeline (`processCerts` / `makePerasCertPoolWriterFromChainDB`) should reject all externally received certificates rather than accepting them unconditionally — analogous to how the UFARM1-10 fix gated `createFund` to only the authorized caller.

### Proof of Concept

1. Attacker connects to a target node via the NTN Peras object-diffusion channel.
2. Attacker sends a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on a competing fork>`.
3. `makePerasCertPoolWriterFromChainDB.opwAddObjects` calls `processCerts` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
4. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
5. `chainSelSync` applies `vpcCertBoost` to the fork containing the attacker's chosen block; if the boosted fork now has greater weight than the current chain, the node switches to it.
6. Expected outcome: honest node adopts the attacker-chosen fork without any legitimate quorum having been reached.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-560)
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
 where
  tracer :: Tracer m (TraceAddPerasCertEvent blk)
  tracer = TraceAddPerasCertEvent >$< cdbTracer

  certRound :: PerasRoundNo
  certRound = getPerasCertRound cert

  boostedBlock :: Point blk
  boostedBlock = getPerasCertBoostedBlock cert

  -- \| Run a block that can exit early with a result value.
  withEarlyExitId :: ExceptT a (Electric m) a -> Electric m a
  withEarlyExitId = fmap (either id id) . runExceptT

  -- \| Exit early with the given result.
  idExitEarly :: a -> ExceptT a (Electric m) b
  idExitEarly = throwE

-- | Return 'True' when the given header should be ignored when adding it
-- because it is too old, i.e., we wouldn't be able to switch to a chain
-- containing the corresponding block because its block number is (weakly) older
-- than that of the immutable tip.
--
-- Special case: the header corresponds to an EBB which has the same block
-- number as the most recent \"immutable\" block. As EBBs share their block
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
