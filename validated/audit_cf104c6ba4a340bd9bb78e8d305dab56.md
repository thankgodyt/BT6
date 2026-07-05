### Title
Unconditional `validatePerasCert` Acceptance Bypasses All Peras Certificate Validation, Enabling Unauthorized Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound Peras certificate without performing any cryptographic or structural check. This stub is wired directly into the production certificate-ingestion path (`makePerasCertPoolWriterFromChainDB`), which is invoked for every certificate received from a peer over the object-diffusion mini-protocol. Because Peras certificates directly drive chain selection (a node switches to a heavier chain based on certificate boosts), any unprivileged peer can inject arbitrary certificates and force the victim node to prefer an attacker-chosen chain.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:** [1](#0-0) 

The comment on line 318 reads *"TODO: degenerate instance for all blks to get things to compile"*. The implementation at lines 353–358 is:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No signature, quorum, committee-membership, round-number, or boosted-block check is performed. Every `PerasCert` value, regardless of content or origin, is wrapped in `Right ValidatedPerasCert` and returned as valid.

**Production call sites — both wired to the network-facing ingestion path:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` (line 126) passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`. This is the production writer used when Peras certificates arrive from peers.

**`processCerts` — accepts the entire batch when validation always succeeds:** [3](#0-2) 

`processCerts` calls `validateCert` (which is `validatePerasCert mkPerasParams`) on every new certificate. Because `validatePerasCert` always returns `Right`, the `partitionEithers` call at line 168 always produces an empty error list, and every certificate is forwarded to `addCert` (line 132: `ChainDB.addPerasCertAsync chainDB`).

**Chain-selection consequence — certificates directly determine the preferred chain:** [4](#0-3) 

`chainSelSync` for `ChainSelAddPerasCert` (line 483) adds the certificate to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block (line 531), potentially switching the node to a different chain. The CHANGELOG confirms: *"the candidate fragment is now selected based on its Peras weight, instead of its length."* [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` containing any `pcCertRound` and any `pcCertBoostedBlock` (a slot + hash pair). After injection:

1. The certificate is stored in `PerasCertDB` with a boost weight of `perasWeight params`.
2. `chainSelectionForBlock` is triggered for the boosted block.
3. If the boosted block is in the VolatileDB and the resulting weighted chain is heavier than the current selection, the node switches to that chain.

This constitutes a **bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation**. An attacker can force an honest node to prefer a non-canonical chain by boosting an adversarial fork with fabricated certificates, violating the Peras safety guarantee that only legitimately certified blocks receive weight boosts.

---

### Likelihood Explanation

The object-diffusion mini-protocol is reachable by any connected peer — no keys, stake, or operator access are required. A `PerasCert` is a small, trivially constructable value (`pcCertRound :: PerasRoundNo`, `pcCertBoostedBlock :: Point blk`). The attacker only needs to know the hash of a block they wish to boost, which is public information on the network. The bypass requires no brute force and no cryptographic material.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion path is enabled in production. At minimum, the implementation must verify:

1. **Aggregate signature** — the certificate carries a valid aggregate BLS/Ed25519 signature from a quorum of eligible committee members for the claimed round and boosted block.
2. **Committee membership and quorum** — the signers are registered pool operators with sufficient combined stake to meet the quorum threshold for the given epoch.
3. **Round validity** — `pcCertRound` is within the acceptable window relative to the current chain tip.
4. **Boosted block existence** — `pcCertBoostedBlock` refers to a block that is plausibly on a valid chain (slot and hash are consistent).

Until real validation is implemented, the certificate-diffusion writer should be disabled or gated behind a feature flag that is off by default, preventing the stub from being reachable on production nodes.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a victim node as a peer via the node-to-node protocol.
2. Attacker sends a `PerasCert` message via the object-diffusion mini-protocol with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <point of a block on an adversarial fork>`
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` returns `Right ValidatedPerasCert{..}` unconditionally.
4. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
5. `chainSelSync` adds the certificate to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
6. If the adversarial fork's weighted length now exceeds the honest chain's weighted length, the node switches forks.

**Expected outcome:** The victim node adopts the adversarial chain, diverging from the honest network — a consensus safety failure triggered by a single unprivileged peer message.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
