### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Arbitrary Chain-Weight Inflation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is a no-op stub that unconditionally returns `Right` for every certificate it receives. Because the production inbound certificate pipeline (`makePerasCertPoolWriterFromChainDB`) wires this stub directly as the validator, any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block, have it accepted without any quorum or signature check, and cause the receiving node to boost that block's chain weight by `perasWeight` (15 blocks). This is the Ouroboros Consensus analog of the PoolTogether "stolen yield" bug: just as anyone could claim unaccounted rebasing yield and attribute it to their own vault to inflate their winning share, any peer can inject unearned weight boosts and attribute them to their preferred chain to manipulate chain selection.

---

### Finding Description

**Root cause — always-`Right` certificate validator**

The universal `BlockSupportsPeras` instance, which applies to all block types, implements `validatePerasCert` as:

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

No signature verification, no quorum check, no committee membership check — every certificate is accepted unconditionally and assigned the full `perasWeight` boost.

**Production inbound pipeline uses the stub**

`makePerasCertPoolWriterFromChainDB` — explicitly documented as the production path for handling chain-selection side-effects — passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate; because the stub always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Chain selection is triggered for the boosted block**

`chainSelSync` in `ChainSel.hs` receives the certificate, stores it in `PerasCertDB`, and immediately triggers `chainSelectionForBlock` for the block named in `pcCertBoostedBlock`: [4](#0-3) 

**Weight snapshot is built directly from stored certificates**

`implGetWeightSnapshot` constructs the `PerasWeightSnapshot` by iterating over every certificate in `pcdsCertsByTicket` and calling `mkPerasWeightSnapshot` with each cert's boosted block and boost value: [5](#0-4) 

`totalWeightOfFragment` then adds this boost on top of the raw block count when comparing chains: [6](#0-5) 

Chain selection prefers the heavier chain via `wsvTotalWeight`: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send one crafted `PerasCert` per round (deduplicated by `PerasRoundNo`) naming any block in the VolatileDB. Each accepted certificate adds `perasWeight = 15` to that block's chain weight. With the default parameters, a single certificate inflates a chain's weight by the equivalent of 15 honest blocks. An attacker who sends certificates for every round on their minority fork can make that fork appear heavier than the honest majority chain, causing the victim node to switch to the attacker's chain. This is a **chain selection manipulation** vulnerability: an honest node is made to prefer a non-canonical, adversarially-controlled chain without the attacker holding any stake or producing any legitimate blocks.

Additionally, because `takeVolatileSuffix` uses `totalWeightOfFragment` to determine the immutability boundary, injected boosts can also push blocks past the `k`-deep finality threshold prematurely, causing incorrect immutability decisions. [8](#0-7) 

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is a standard node-to-node protocol reachable by any peer that can establish a connection. The inbound handler (`objectDiffusionInbound`) accepts certificate objects from any connected peer and passes them directly to `opwAddObjects`. No authentication, stake ownership, or prior trust is required. The only per-round deduplication (`Set.member roundNo certIds`) limits one certificate per round number, but an attacker can cover many rounds by sending one certificate per round. This is reachable from a private testnet or any network where the Peras ObjectDiffusion protocol is active. [9](#0-8) 

---

### Recommendation

1. **Replace the stub with real validation** before the ObjectDiffusion pipeline is enabled in any network-connected context. `validatePerasCert` must verify the aggregate BLS signature against the claimed committee and confirm that the total voting stake meets `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`. [10](#0-9) 

2. **Gate the ObjectDiffusion protocol** behind a feature flag or era check so that the certificate inbound handler is not reachable until real validation is wired in.

3. **Add a validation-required invariant** in `processCerts`: if the supplied `validateCert` function is the stub (or if Peras is active on the network), assert that validation is non-trivial before accepting any certificate. [11](#0-10) 

---

### Proof of Concept

**Setup**: Two nodes A (honest) and B (attacker) on a private testnet with the ObjectDiffusion protocol enabled.

1. Node A has a current chain of length 100 (weight 100).
2. Node B produces a fork of length 90 starting from block 80 (weight 90 — normally rejected).
3. Node B sends 11 crafted `PerasCert` objects to node A via ObjectDiffusion, each naming a different block on B's fork (rounds 1–11).
4. Because `validatePerasCert` always returns `Right`, all 11 certificates are accepted by node A and stored in its `PerasCertDB`.
5. `implGetWeightSnapshot` builds a snapshot with 11 × 15 = 165 boost weight on B's fork blocks.
6. `totalWeightOfFragment` for B's fork = 90 (blocks) + 165 (boost) = 255 > 100 (A's chain weight).
7. `preferCandidate` returns `ShouldSwitch` and node A rolls back to block 80 and adopts B's fork.

Node A has been made to adopt an adversarially-controlled minority chain without B holding any stake or producing any legitimate blocks beyond the fork point. [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L319-330)
```haskell
-- | Take the longest suffix of the given fragment with total weight
-- ('totalWeightOfFragment') at most @k@. This is the volatile suffix of blocks
-- which are subject to rollback.
--
-- If the total weight of the input fragment is at least @k@, then the anchor of
-- the output fragment is the most recent point on the input fragment that is
-- buried under at least weight @k@ (also counting the weight boost of that
-- point).
--
-- See 'mkPerasWeightSnapshot' for context.
--
-- >>> :{
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L354-411)
```haskell
      CollectObjects requestedIds collectedObjects -> WithEffect $ do
        let requestedIdsSet = Set.fromList requestedIds
            obtainedIdsSet = Set.fromList (opwObjectId <$> collectedObjects)

        -- To start with we have to verify that the objects they have sent us are
        -- exactly the objects we asked for, not more, not less.
        when (requestedIdsSet /= obtainedIdsSet) $
          let reqButNotRecvd = requestedIdsSet `Set.difference` obtainedIdsSet
              recvButNotReq = obtainedIdsSet `Set.difference` requestedIdsSet
           in throwIO
                ( ProtocolErrorObjectsDifferentThanRequested @objectId @object
                    reqButNotRecvd
                    recvButNotReq
                )

        traceWith tracer $
          TraceObjectDiffusionInboundCollectedObjects (length collectedObjects)

        -- We update 'pendingObjects' with the newly obtained objects
        let pendingObjects' =
              foldl'
                (\accMap object -> Map.insert (opwObjectId object) (Just object) accMap)
                (pendingObjects st)
                collectedObjects

            -- We then find the longest prefix of 'outstandingFifo' for which we have
            -- all the corresponding IDs in 'pendingObjects'.
            -- We remove this prefix from 'outstandingFifo'.
            (objectIdsToAck, outstandingFifo') =
              Seq.spanl (`Map.member` pendingObjects') (outstandingFifo st)

            -- And also remove these entries from 'pendingObjects'.
            --
            -- Note that unlike in TX-Submission, we made sure the outstanding FIFO
            -- couldn't have duplicate IDs, so we don't have to worry about re-adding
            -- the duplicate IDs to 'pendingObjects' for future acknowledgment.
            pendingObjects'' =
              Foldable.foldl'
                (flip Map.delete)
                pendingObjects'
                objectIdsToAck

            -- These are the objects we need to submit to the object pool
            --
            -- Note that objects are submitted in the same order as the order of
            -- announcement, for consistency with TX-Submission, and for
            -- simplicity of implementation/acknowledgment. However this is not
            -- a strict requirement of the protocol, so we could consider
            -- changing this in the future if we wanted to (e.g. for
            -- optimizations reasons).
            objectsToAck =
              catMaybes $
                (((Map.!) pendingObjects') <$> toList objectIdsToAck)

        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))
```
