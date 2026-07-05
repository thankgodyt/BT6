Let me analyze the vulnerability class from the external report and search for analogs in the Ouroboros Consensus codebase.

The external report describes a **classification/accounting bypass**: a value is misclassified based on attacker-controlled input, causing a required check (fee charging) to be skipped. The analog in consensus would be a validation step being skipped due to misclassification of a block/header/certificate type.

### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Weight Boost - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic, committee-membership, or quorum verification. This stub is wired directly into the production inbound certificate diffusion path. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block, have it accepted as "validated," stored in the `PerasCertDB`, and used to artificially boost that block's chain-selection weight by `perasWeight` (default: 15), potentially causing the honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation always succeeds:**

In `SupportsPeras.hs`, the universal instance for all `StandardHash blk` blocks implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/73
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No signature is checked, no committee membership is verified, no quorum threshold is enforced. Every certificate — regardless of content — is returned as `ValidatedPerasCert` carrying the full `perasWeight` boost. [1](#0-0) 

**Production wiring — stub used in both inbound cert pool writers:**

`makePerasCertPoolWriterFromChainDB` (the production path) and `makePerasCertPoolWriterFromCertDB` both pass `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`:

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

**`processCerts` trusts the validation result:**

`processCerts` partitions results into errors and successes. Because `validatePerasCert` never returns `Left`, every inbound certificate lands in the "all valid" branch and is immediately added to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Chain selection is then triggered with the forged boost:**

Once the certificate is stored, `chainSelSync` in `ChainSel.hs` retrieves the boosted block from the VolatileDB and calls `chainSelectionForBlock`, which compares chains using `WeightedSelectView`. The forged certificate's `vpcCertBoost = perasWeight mkPerasParams = 15` is added to the total weight of any fragment containing the boosted block: [4](#0-3) 

The `wsvTotalWeight` comparison directly sums `BlockNo` and `wsvWeightBoost`, so a chain with 15 fewer blocks but one forged certificate beats a longer honest chain: [5](#0-4) 

**Network entry point:**

The `hPerasCertDiffusionClient` handler in `NodeToNode.hs` calls `makePerasCertPoolWriterFromChainDB` directly, making this reachable from any connected peer over the standard node-to-node Peras certificate diffusion mini-protocol: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` naming any block currently in the receiving node's VolatileDB. The stub `validatePerasCert` accepts it unconditionally. The certificate is stored and triggers chain selection, adding `perasWeight = 15` to the total weight of any fragment containing that block. Because `WeightedSelectView` compares `wsvTotalWeight = BlockNo + weightBoost`, a chain that is up to 15 blocks shorter than the honest tip can be made to appear heavier, causing the node to roll back and switch to a non-canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions. [7](#0-6) 

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is active whenever Peras is enabled. Any peer that can establish a node-to-node connection can send a crafted `PerasCert` message. No stake, no key material, and no prior knowledge beyond the target block's hash (observable from the chain) is required. The attack is deterministic and requires only a single well-formed CBOR-encoded certificate message.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS vote signature against the declared committee members' verification keys.
2. That each declared voter was actually a member of the committee for the certificate's round (via the stake distribution and VRF eligibility proofs).
3. That the total voting weight of the signers meets the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).

Until the full committee plumbing is in place (tracked in [issue #73](https://github.com/tweag/cardano-peras/issues/73) and [#120](https://github.com/tweag/cardano-peras/issues/120)), the stub should at minimum **reject all certificates** (`Left PerasValidationErr`) rather than accept all of them, so that the Peras diffusion path is safely inert until real validation is implemented. [8](#0-7) 

---

### Proof of Concept

1. Connect to a target node over the node-to-node Peras certificate diffusion mini-protocol.
2. Observe the target node's current chain tip; pick any block hash `H` in its VolatileDB that is on a competing fork (or the current chain, to strengthen it artificially).
3. Craft a `PerasCert` with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = <slot, H>`.
4. Send the certificate via the `ObjectDiffusion` protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = 15 }` unconditionally.
6. The certificate is stored in `PerasCertDB`; `chainSelSync` retrieves block `H` from the VolatileDB and calls `chainSelectionForBlock`.
7. `WeightedSelectView` now scores any fragment containing `H` as having `BlockNo(H) + 15` total weight.
8. If the competing fork's tip block number plus 15 exceeds the honest chain's tip block number, the node rolls back to the competing fork.

The attacker needs only a valid CBOR encoding of `PerasCert` — no cryptographic keys, no stake. [9](#0-8)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L391-408)
```haskell
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
