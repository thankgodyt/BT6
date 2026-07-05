### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `PerasCertDiffusion` inbound miniprotocol handler accepts Peras certificates from any peer and passes them through a stub `validatePerasCert` that unconditionally returns `Right` without performing any cryptographic or committee-membership verification. Accepted certificates are stored in the `PerasCertDB` and their weight boost is applied directly to chain selection via `PerasWeightSnapshot`. An unprivileged peer can therefore inject a crafted `PerasCert` that boosts an arbitrary block on a fork, causing the honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validator always succeeds.**

The `BlockSupportsPeras` instance for all blocks defines `validatePerasCert` as:

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

No signature is checked, no committee membership is verified, no round-number bounds are enforced. Every inbound `PerasCert` is unconditionally promoted to a `ValidatedPerasCert` carrying a non-zero `vpcCertBoost`.

**Entry path — production inbound handler.**

`makePerasCertPoolWriterFromChainDB` is wired directly into the node-to-node `hPerasCertDiffusionClient` handler:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator: [3](#0-2) 

`processCerts` partitions results with `partitionEithers`; because `validatePerasCert` never returns `Left`, every certificate passes and is added to the DB: [4](#0-3) 

**Chain-selection effect.**

`chainSelSync` processes each accepted certificate: it stores it in `PerasCertDB` and, if the boosted block is present in the `VolatileDB`, immediately triggers `chainSelectionForBlock`: [5](#0-4) 

`implGetWeightSnapshot` materialises the stored certificates into a `PerasWeightSnapshot` keyed by boosted block point: [6](#0-5) 

`weightedSelectView` then adds this boost to the `wsvTotalWeight` used by `preferAnchoredCandidate` to compare candidate chains: [7](#0-6) 

A fork whose tip block carries a fake boost can therefore exceed the total weight of the honest chain, causing the node to switch.

---

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An attacker who knows any block hash present in the target node's `VolatileDB` (block hashes are public) can craft a `PerasCert` that boosts that block. Because `validatePerasCert` performs no verification, the certificate is accepted, stored, and its boost is applied to chain selection. If the boosted block is on a fork, the node may switch to that fork even though it is shorter or less secure than the honest chain. This violates the Ouroboros chain-selection invariant and constitutes a chain-selection safety failure reachable by any unprivileged peer.

If the boosted block is not yet in the `VolatileDB`, the certificate is still stored; when the block arrives later, the pre-injected boost is applied retroactively, giving the attacker a persistent, durable influence over future chain selection.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is unconditionally registered for every node-to-node connection. No special privileges, stake, or keys are required. Block hashes on recent forks are observable from the public network. The attack requires only a TCP connection to the target node and knowledge of one fork-block hash in its volatile window. The stub is explicitly marked as incomplete with a TODO referencing issue #120, confirming the missing validation is a known gap rather than an intentional design.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the declared committee members' verification keys.
2. That the signers are eligible committee members for the claimed round (VRF-based eligibility).
3. That the aggregate stake of the signers meets the quorum threshold.
4. That the round number is within the valid window relative to the current chain tip.

Until real validation is in place, the `PerasCertDiffusion` inbound handler should either be disabled or should reject all inbound certificates before they reach `processCerts`.

---

### Proof of Concept

```
1. Attacker connects to an honest node via the node-to-node protocol.

2. Attacker observes the network and learns hash H of a block B that is
   in the node's VolatileDB on a fork (shorter than the current chain).

3. Attacker sends a PerasCert via the PerasCertDiffusion miniprotocol:
     PerasCert { pcCertRound    = <any round not yet in DB>
               , pcCertBoostedBlock = BlockPoint <slot of B> H }

4. makePerasCertPoolWriterFromChainDB → processCerts →
   validatePerasCert mkPerasParams cert
   returns Right (ValidatedPerasCert { vpcCert = cert
                                     , vpcCertBoost = perasWeight mkPerasParams })
   (no signature check, no committee check)

5. The certificate is stored in PerasCertDB.

6. chainSelSync (ChainSelAddPerasCert) finds B in the VolatileDB and
   calls chainSelectionForBlock for B.

7. preferAnchoredCandidate computes WeightedSelectView for the fork
   containing B; wsvWeightBoost is now non-zero due to the fake cert.

8. If wsvTotalWeight(fork) > wsvTotalWeight(current chain),
   the node switches to the fork — a chain-selection safety failure
   induced by an unprivileged peer with no cryptographic credentials.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-88)
```haskell
instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT

```
