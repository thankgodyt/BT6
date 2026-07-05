### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Sent Certificate, Enabling Chain-Selection Manipulation - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used for all block types contains a `validatePerasCert` implementation that is an explicit stub: it unconditionally returns `Right` (success) for every certificate, performing no cryptographic, quorum, or committee-membership checks. Any unprivileged peer connected via the Peras object-diffusion mini-protocol can therefore inject a crafted `PerasCert` that boosts an arbitrary block on a fork chain. Because the boosted weight is fed directly into `preferAnchoredCandidate`, the node will switch to the adversarial fork if it is within `perasWeight` (default: 15) blocks of the current tip — a chain-selection safety failure reachable by any peer.

---

### Finding Description

**Root cause — stub validation always succeeds**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

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

No signature, quorum, committee-membership, round-number range, or boosted-block existence check is performed. Every certificate is accepted as `ValidatedPerasCert` with the full `perasWeight` boost (15 by default). [2](#0-1) 

**Attacker-controlled entry path — inbound certificate handler**

The production inbound handler `makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

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
``` [3](#0-2) 

`processCerts` calls `validateCert` on each inbound cert; if all pass (they always do), they are added to the ChainDB via `addPerasCertAsync`: [4](#0-3) 

**Chain-selection consequence**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. The handler in `chainSelSync` looks up the boosted block in the VolatileDB and, if found, calls `chainSelectionForBlock` for it: [5](#0-4) 

`chainSelectionForBlock` calls `preferAnchoredCandidate`, which — when Peras is active — computes `wsvTotalWeight = blockNo + weightBoost` for each candidate fragment: [6](#0-5) 

A fork chain whose boosted block receives `PerasWeight 15` can therefore beat the honest chain even if it is up to 15 blocks shorter. The node switches to the adversarial fork.

---

### Impact Explanation

**Category**: High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

An adversary who controls one peer connection can:
1. Identify (or produce) a fork block `B` in the victim node's VolatileDB that is up to 15 blocks behind the current tip.
2. Send a crafted `PerasCert{pcCertRound = r, pcCertBoostedBlock = point(B)}` over the Peras object-diffusion mini-protocol.
3. The cert passes `validatePerasCert` unconditionally, is stored, and triggers chain selection.
4. The fork containing `B` now has `totalWeight = blockNo(B) + 15`; if this exceeds the honest chain's `blockNo`, the node switches.

This violates the Praos/Peras Common Prefix property: an honest node's selection diverges from the canonical chain without any stake-majority requirement, purely from a single crafted network message.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is reachable by any peer the node connects to (no privileged role required). The stub is in production source code, not a test file. The `mkPerasParams` hardcoded default is used in both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`. The attack requires only that the adversarial peer know a block hash in the victim's VolatileDB — information obtainable via ChainSync. No cryptographic break, no stake, and no operator compromise is needed.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The aggregate BLS signature over `(roundNo, boostedBlock)` against the committee's aggregate public key.
- That the voter bitmap represents a quorum of stake (≥ `perasQuorumStakeThreshold`).
- That the `pcCertRound` is within the valid acceptance window.
- That the `pcCertBoostedBlock` refers to a block that actually exists on a known chain.

Until the real implementation is in place, the node should refuse to process inbound `PerasCert` messages from peers (i.e., disable the Peras object-diffusion writer) rather than accept all of them unconditionally.

---

### Proof of Concept

```
Attacker peer  →  sends PerasCert { pcCertRound = 42,
                                     pcCertBoostedBlock = point(forkBlock) }
                  over Peras object-diffusion mini-protocol

processCerts calls validatePerasCert mkPerasParams cert
  → always returns Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })

addPerasCertAsync enqueues ChainSelAddPerasCert

chainSelSync:
  boostedBlock = forkBlock  (in VolatileDB, not on current chain)
  → chainSelectionForBlock triggered for forkBlock

preferAnchoredCandidate (Peras path):
  oursSuffix  totalWeight = blockNo(ourTip)  + 0   (no boost)
  candSuffix  totalWeight = blockNo(forkTip) + 15  (boosted)

  if blockNo(forkTip) + 15 > blockNo(ourTip):
    ShouldSwitch → node adopts adversarial fork
```

The default `perasWeight = 15` means any fork within 15 blocks of the current tip can be forced onto the victim node by a single peer message, with no stake or cryptographic capability required. [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```
