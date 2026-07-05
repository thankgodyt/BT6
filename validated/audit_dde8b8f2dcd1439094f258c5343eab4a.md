### Title
`validatePerasCert` Unconditionally Returns Success — Peer-Injected Peras Certificates Bypass All Cryptographic Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole `BlockSupportsPeras` instance in the codebase implements `validatePerasCert` as a function that unconditionally returns `Right` (success) without performing any cryptographic or committee-membership checks. Because this is the only instance, every Peras certificate received from an unprivileged peer over the object-diffusion mini-protocol is accepted as valid and forwarded to chain selection, where it boosts an arbitrary block. This is a direct analog to M-02: just as `approve()` never calls `transferSanity()`, `validatePerasCert` never performs the checks its type contract requires.

---

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the repository is the degenerate catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This implementation accepts every certificate unconditionally — no signature check, no committee-membership check, no round-number plausibility check.

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes this function directly to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

Inside `processCerts`, the result of `validateCert <$> certsNotAlreadyInDb` is pattern-matched: if the left list is empty (all `Right`), every certificate is added. Because `validatePerasCert` always returns `Right`, the left list is always empty, and every certificate is unconditionally forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message, which is processed by `chainSelSync`, where the certificate's boosted block is used to trigger chain selection: [4](#0-3) 

---

### Impact Explanation

A Peras certificate boosts a block in chain selection by adding `vpcCertBoost` weight to it. Because `validatePerasCert` always succeeds, an unprivileged peer can craft a `PerasCert` naming any `(round, block-point)` pair and have it accepted. The node will then treat that block as boosted during chain selection, potentially switching to a non-canonical or attacker-controlled fork that would otherwise not be preferred. This constitutes a **bypass of Peras certificate validation** enabling unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: bypass of certificate/vote verification checks" impact category.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any peer the node connects to. No special privileges, keys, or stake are required to send a `PerasCert` message. The only existing guard — the round-number deduplication check (`Set.member roundNo alreadyInDb`) — only prevents the same round from being submitted twice; it does not validate the certificate's authenticity. Any peer that has not yet sent a certificate for a given round can inject one for any block.

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that verifies:
1. The certificate's cryptographic aggregate signature against the claimed committee members.
2. That the claimed voters were eligible committee members for the stated round (VRF-based sortition proof).
3. That the boosted block point is plausible (e.g., within the current chain's recent history).

Until a real implementation is available, the object-diffusion inbound path for Peras certificates should not be enabled in any network-facing configuration, or should gate acceptance on a feature flag that is off by default.

---

### Proof of Concept

1. Connect to a node running this code as an unprivileged peer via the object-diffusion mini-protocol.
2. Send a `PerasCert` with `pcCertRound = R` (any round not yet in the DB) and `pcCertBoostedBlock = P` (any block point, including one on an attacker-controlled fork).
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}` unconditionally.
4. The certificate is added to `PerasCertDB` and `ChainSelAddPerasCert` is enqueued.
5. `chainSelSync` processes the message: if the boosted block is reachable, chain selection now treats it as having additional Peras weight, potentially switching the node's selected chain to the attacker's fork. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-328)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

-- | Add a Peras vote to the VoteDB contained in the ChainDB, and if this
-- results in a new cert being generated, add that cert /asynchronously/ to
-- the ChainDB as well.
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
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
```
