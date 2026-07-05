### Title
Unconditional No-Op `validatePerasCert` Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` typeclass provides a single catch-all instance (`instance StandardHash blk => BlockSupportsPeras blk`) whose `validatePerasCert` implementation unconditionally returns `Right` — accepting every certificate without performing any cryptographic or structural check. This no-op validator is wired directly into the production Peras certificate inbound path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send a crafted `PerasCert` message that passes "validation", is stored in the `PerasCertDB`, and triggers chain selection with an artificial weight boost, potentially causing an honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — the no-op validator:**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` defines the only `BlockSupportsPeras` instance as a degenerate catch-all:

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

This instance covers every block type including `CardanoBlock`. No signature, committee membership, round validity, or boosted-block existence check is performed. The function is structurally identical to the "no-op fallback" in the referenced report: the call appears to validate but silently succeeds for all inputs.

**Production wiring — the inbound certificate path:**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` passes this no-op directly as the `validateCert` argument to `processCerts`:

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

`processCerts` calls `validateCert` on every inbound certificate and, if all return `Right`, passes them to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer is accepted.

**Chain selection impact:**

`addCert` resolves to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. The background `addBlockRunner` dequeues it and calls `chainSelSync`, which:

1. Stores the certificate in `PerasCertDB`.
2. Looks up the boosted block in the `VolatileDB`.
3. Calls `chainSelectionForBlock` for that block. [4](#0-3) 

Chain selection uses `WeightedSelectView`, where `wsvTotalWeight = BlockNo + WeightBoost`. The boost assigned by the no-op validator is `perasWeight mkPerasParams = PerasWeight 15`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

A fork whose tip is up to 15 blocks behind the current chain tip can be made to appear heavier by injecting a single crafted certificate.

**Attacker-controlled entry path:**

The Peras certificate object-diffusion mini-protocol is reachable from any connected peer. The peer sends a `PerasCert` with an attacker-chosen `pcCertRound` and `pcCertBoostedBlock` pointing to a block already in the target node's `VolatileDB`. The certificate passes the no-op `validatePerasCert`, is stored, and triggers chain selection for the boosted block.

### Impact Explanation

**High.** Chain selection, rollback, and header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

An adversary with a fork that is up to `perasWeight mkPerasParams = 15` blocks shorter than the honest chain can inject a single crafted certificate to make the target node switch to that fork. With multiple certificates (one per round, deduplicated by `pcCertRound`), the attacker can accumulate boosts across multiple blocks on the adversarial fork, amplifying the effect. This directly violates the Peras chain-selection invariant that only legitimately quorum-certified blocks receive a weight boost.

### Likelihood Explanation

**Medium.** The Peras object-diffusion mini-protocol is active in the codebase and wired to the production `ChainDB`. Any peer that can establish a node-to-node connection can send `PerasCert` messages. The only precondition is that the boosted block's hash exists in the target node's `VolatileDB`, which is trivially satisfied for any recently-seen block. No keys, stake, or privileged access are required.

### Recommendation

Replace the degenerate catch-all `validatePerasCert` with a real implementation before the Peras certificate diffusion path is enabled in production. At minimum, add a guard in `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` that rejects all certificates when no real validator is available (i.e., return `Left PerasValidationErr` unconditionally rather than `Right`), so that the no-op does not silently accept adversarial input. Track the real implementation under the referenced issue (https://github.com/tweag/cardano-peras/issues/120).

### Proof of Concept

1. Establish a node-to-node connection to a target Cardano node running this codebase.
2. Observe a block hash `H` present in the target's `VolatileDB` that is on a fork `F` shorter than the current chain by ≤ 15 blocks.
3. Send a `PerasCert` message with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = BlockPoint <slot> H`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=PerasWeight 15}` unconditionally.
5. The certificate is stored in `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
6. `chainSelSync` triggers `chainSelectionForBlock` for the block at `H`.
7. `weightedSelectView` computes `wsvTotalWeight` for fork `F` as `BlockNo(tip of F) + 15`, which now exceeds `BlockNo(tip of current chain) + 0`.
8. The node switches to fork `F`, diverging from the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
