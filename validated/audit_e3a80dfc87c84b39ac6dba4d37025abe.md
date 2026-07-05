### Title
Peras Certificate Validation Universally Bypassed — Any Peer Can Inject Fraudulent Certificates to Manipulate Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance for all `StandardHash blk` implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound certificate without any cryptographic or structural check. This stub is wired directly into the production `PerasCertDiffusion` mini-protocol handler via `makePerasCertPoolWriterFromChainDB`. Any unprivileged peer can send a crafted `PerasCert` that passes validation, is stored in the `PerasCertDB`, and triggers chain selection with a `PerasWeight 15` boost applied to an attacker-chosen block, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify committee membership, BLS aggregate signature, VRF eligibility, and round validity before a certificate may influence chain selection. The only instance in the codebase is a universal placeholder:

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

No signature is present in the degenerate `PerasCert blk` data type (it only carries `pcCertRound` and `pcCertBoostedBlock`), and no check of any kind is performed. Every certificate unconditionally receives `vpcCertBoost = perasWeight params = PerasWeight 15`.

**Production wiring — cert diffusion handler:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

This writer is installed as the live `hPerasCertDiffusionClient` handler in `NodeToNode.hs`:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

**`processCerts` logic — all-or-nothing batch acceptance:**

`processCerts` calls `validateCert` on each new certificate. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is added to the DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

**Chain selection consequence:**

`ChainDB.addPerasCertAsync` feeds the accepted cert into `chainSelSync`, which applies the `PerasWeight 15` boost to the `pcCertBoostedBlock` and re-runs chain selection. If the boosted block is on a competing fork, the node may switch to that fork:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

**`mkPerasParams` — concrete boost value:**

```haskell
perasWeight = PerasWeight 15
``` [6](#0-5) 

---

### Impact Explanation

**Classification:** Critical — bypass of Peras certificate validation that enables unauthorized certificate acceptance and chain-selection manipulation by an unprivileged peer.

An attacker who connects to a node as a normal peer can send a `PerasCert` message over the `PerasCertDiffusion` mini-protocol naming any block in the node's VolatileDB as the boosted block. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and triggers chain selection with a `PerasWeight 15` advantage for the attacker-chosen block. If the attacker's target block is on a competing fork, the node may switch to that fork, diverging from the honest chain. This directly violates the Peras security model, which requires a quorum of legitimate committee members (holding BLS keys and satisfying VRF eligibility) to produce a valid certificate.

---

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is unconditionally enabled in the production `NodeToNode` handler. Any peer that establishes a connection can send `PerasCert` messages. No stake, no key material, and no committee membership is required. The only constraint is that the `pcCertRound` must not already be present in the `PerasCertDB` (one cert per round), but an attacker can target any round not yet certified. The `PerasWeight 15` boost is a concrete, non-zero value that actively participates in chain selection comparisons.

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that:
1. Verifies the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregate public key of the declared voters.
2. Checks that each declared voter is a registered committee member with sufficient stake (VRF eligibility for non-persistent members).
3. Verifies that the total stake of the voters meets the quorum threshold (`perasQuorumStakeThreshold`).
4. Validates that `pcCertRound` is within the acceptable range (not too old per `perasCertMaxRounds`).

Until the real implementation is available, the `PerasCertDiffusion` inbound handler should be disabled or gated behind a feature flag that is off by default, preventing untrusted peers from submitting certificates.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node as a normal peer (no privileged access required).
2. Attacker sends a `PerasCert` message over the `PerasCertDiffusion` mini-protocol with:
   - `pcCertRound = R` (any round not yet in the node's `PerasCertDB`)
   - `pcCertBoostedBlock = Point slotN hashOfAdversarialBlock` (a block the attacker wants to boost, present in the node's VolatileDB)
3. `objectDiffusionInbound` → `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
4. `ChainDB.addPerasCertAsync` is called; `chainSelSync` applies the `PerasWeight 15` boost to `hashOfAdversarialBlock` and re-runs chain selection.
5. If the adversarial block is on a fork that is now heavier than the current selection (by 15 weight units), the node switches to the adversarial chain.

The degenerate `PerasCert blk` data type carries no signature field, so there is no cryptographic material to forge — the attacker simply constructs a valid CBOR-encoded `PerasCert` with the desired `pcCertRound` and `pcCertBoostedBlock` and sends it over the wire. [7](#0-6) [8](#0-7) [3](#0-2)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
