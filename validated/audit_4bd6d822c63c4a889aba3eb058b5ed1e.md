### Title
Peras Certificate Validation Permanently Bypassed — Any Peer Can Forge Certificates to Manipulate Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `validatePerasCert` function, which is the sole gate between a peer-supplied Peras certificate and its acceptance into the `PerasCertDB` and chain selection, is a stub that unconditionally returns `Right` for every input. No cryptographic signature, no committee membership, and no quorum check is performed. An unprivileged peer can send any crafted `PerasCert` message, have it accepted as a `ValidatedPerasCert`, and cause the receiving node to re-run chain selection with an artificial weight boost applied to an attacker-chosen block, potentially making the node prefer a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a permanent no-op:**

The `BlockSupportsPeras` type class declares `validatePerasCert` as the validation gate for inbound certificates. The only deployed instance (a catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements it as:

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

This function ignores every field of `cert` and every field of `params` except `perasWeight`. It performs no signature verification, no committee membership check, and no quorum check. It always succeeds.

**Attacker-controlled entry path — the Peras certificate diffusion pool writer:**

Inbound certificates received from a peer are processed by `processCerts` in `makePerasCertPoolWriterFromChainDB`. The `validateCert` argument passed to `processCerts` is exactly `validatePerasCert mkPerasParams`:

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
``` [2](#0-1) 

Inside `processCerts`, the result of `validateCert` is the only gate before `addCert` is called:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer passes.

**Chain selection consequence:**

`addPerasCertAsync` enqueues the accepted certificate into the `ChainSelQueue`. `chainSelSync` then processes it: it adds the certificate to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block, which re-evaluates whether the node should switch to a fork containing that block, now weighted by `vpcCertBoost = perasWeight mkPerasParams = PerasWeight 15`. [4](#0-3) 

The Peras weight boost is additive to block number in chain selection. A chain of length `N` with a forged boost of 15 beats a canonical chain of length `N+14` with no boost. [5](#0-4) 

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An adversarial peer can:
1. Identify a block on a minority fork (or a block it controls) in the node's VolatileDB.
2. Send a crafted `PerasCert` naming that block as `pcCertBoostedBlock` with a fresh `pcCertRound`.
3. The node accepts the certificate without any verification, applies a weight boost of 15 to that block, and re-runs chain selection.
4. If the boosted fork's total weight (block number + 15) exceeds the current selection's weight, the node switches to the adversary's preferred chain.

This directly violates the Peras security assumption that only a certificate backed by a quorum of honest committee members can boost a block.

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is an externally reachable network endpoint. Any peer that connects to a Peras-enabled node can send `PerasCert` messages. The `processCerts` function is the production handler for all inbound certificates from peers. No privilege, key material, or stake is required. The only precondition is that the targeted block must be present in the node's VolatileDB (i.e., not yet immutable), which is trivially satisfiable for any recently diffused block.

### Recommendation

Implement the actual cryptographic and committee-membership validation inside `validatePerasCert`. At minimum, the implementation must:
1. Verify the aggregate BLS/committee signature over the certificate content.
2. Verify that the signers are eligible committee members for the claimed round.
3. Verify that the aggregate stake of the signers meets the quorum threshold (`perasQuorumStakeThreshold`).

Until this is implemented, the `validatePerasCert` stub must not be wired into any production code path that accepts peer-supplied certificates and feeds them into chain selection. The `TODO` comments referencing issue `https://github.com/tweag/cardano-peras/issues/120` confirm this is a known incomplete implementation. [6](#0-5) 

### Proof of Concept

1. Connect to a Peras-enabled node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound = <any round not yet in the node's PerasCertDB>`
   - `pcCertBoostedBlock = <point of a block on a minority fork present in the node's VolatileDB>`
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` unconditionally.
5. `addPerasCertAsync` enqueues the certificate; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
6. The node's chain selection now computes `totalWeight(minority fork) = blockNo + 15`. If this exceeds `totalWeight(canonical chain) = blockNo_canonical`, the node switches to the minority fork.

The attacker needs no keys, no stake, and no special protocol privileges — only a peer connection to a Peras-enabled node.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-268)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)

```
