### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Fake Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — which is the **only** production instance for all block types — implements `validatePerasCert` as an unconditional `Right`, accepting every inbound certificate without any cryptographic, quorum, or round validity check. An unprivileged peer can send a crafted `PerasCert` boosting any block in the VolatileDB; the certificate passes validation, is stored in the `PerasCertDB`, and triggers chain selection that applies a `perasWeight = 15` boost to the attacker-chosen block, potentially causing the honest node to switch to an adversarially controlled fork.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must verify an inbound Peras certificate before it is stored and used in chain selection. The universal degenerate instance (lines 318–358) that covers all block types implements this gate as:

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
``` [1](#0-0) 

No signature is verified, no quorum is checked, no round bounds are enforced, and no membership in the voting committee is confirmed. The function returns `Right` for every input unconditionally.

This instance is wired directly into the production certificate inbound path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, if all return `Right`, adds them via `addCert`: [3](#0-2) 

Once accepted, `chainSelSync` processes the certificate: it adds it to the `PerasCertDB` and, if the boosted block is in the VolatileDB, immediately triggers `chainSelectionForBlock` for that block with the full `perasWeight` boost applied: [4](#0-3) 

The default `perasWeight` is 15, meaning the boosted block's chain is treated as 15 blocks heavier than it actually is: [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and round number, send it over the Peras certificate object-diffusion mini-protocol, and have it accepted without any check. The receiving node will:

1. Store the fake certificate in its `PerasCertDB`.
2. Trigger chain selection for the boosted block, applying a weight of 15 extra blocks.
3. Potentially switch its selected chain to the adversarially boosted fork.

This is a **chain selection safety failure**: an honest node can be made to prefer a non-canonical chain solely on the basis of a forged certificate, with no stake, no VRF proof, and no quorum of votes required. The impact matches: *"Bypass of Peras certificate checks that enables unauthorized certificate acceptance"* and *"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

The entry point is the public Peras certificate object-diffusion mini-protocol, reachable by any peer that connects to the node. No credentials, stake, or key material are required. The attacker only needs to construct a valid CBOR-encoded `PerasCert` (a round number and a block point), which is trivially serialisable. The vulnerability is present in the only production instance of `BlockSupportsPeras` and is active whenever the Peras certificate diffusion subsystem is running.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:

1. Verifies the aggregate BLS signature (or equivalent cryptographic proof) embedded in the certificate against the known voting committee for the claimed round.
2. Confirms the certificate's round number falls within the valid acceptance window (`perasCertMaxRounds`).
3. Confirms the boosted block point is a known, valid block.

Until a full implementation is ready, the degenerate instance should at minimum **reject all inbound certificates** (`Left PerasValidationErr`) rather than accept them all, so that the Peras certificate diffusion path is safely disabled rather than silently bypassed.

The `PerasValidationErr` data type should also be enriched with concrete error variants (tracked in issue #120) to enable meaningful peer punishment on rejection. [6](#0-5) 

---

### Proof of Concept

Using any peer connection to a node with Peras certificate diffusion enabled:

1. Observe a block hash `H` on a minority fork in the node's VolatileDB (e.g., via ChainSync).
2. Construct a `PerasCert` with `pcCertRound = <any valid round>` and `pcCertBoostedBlock = H`.
3. Serialise it as CBOR (two-field list: round number + block point) and send it via the object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
5. `addPerasCertAsync` enqueues the certificate; `chainSelSync` applies a weight-15 boost to block `H` and re-runs chain selection.
6. If the fork containing `H` is within `k` blocks of the current tip, the node switches to it.

No stake, no VRF proof, no quorum of votes is required at any step. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-176)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
```
