### Title
`validatePerasCert` Unconditionally Accepts All Peer-Supplied Peras Certificates Without Cryptographic Validation, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural validation. Because the Peras cert diffusion mini-protocol is wired up and active in `mkHandlers`, any unprivileged peer can inject an arbitrary `PerasCert` that names any block point as its boosted target. The accepted certificate is stored in the `PerasCertDB` and immediately triggers chain selection for the boosted block, artificially inflating that chain's Peras weight and potentially causing the node to switch away from the canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

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

Every certificate, regardless of its cryptographic content, round number, or boosted block, is accepted and assigned a boost of `perasWeight params`.

**Entry path — cert diffusion mini-protocol is unconditionally active:**

In `mkHandlers`, the Peras cert diffusion client is wired up without any feature-flag guard: [2](#0-1) 

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
```

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, `processCerts` never throws `PerasCertValidationError`; every inbound cert is forwarded to `ChainDB.addPerasCertAsync`.

**Chain selection impact — accepted cert triggers re-evaluation:**

`chainSelSync` processes the cert, adds it to `cdbPerasCertDB`, and — if the boosted block is present in the `VolatileDB` — immediately calls `chainSelectionForBlock` for that block: [4](#0-3) 

Chain selection then uses `preferAnchoredCandidate`, which computes `weightBoostOfFragment` from the now-updated `PerasWeightSnapshot`. A candidate chain containing the attacker-chosen block gains `perasWeight mkPerasParams` additional weight per injected certificate: [5](#0-4) 

The `wsvTotalWeight` comparison in `WeightedSelectView.preferCandidate` then uses this inflated weight to decide whether to switch chains: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` naming any block point as `pcCertBoostedBlock`. Because `validatePerasCert` performs no validation, the cert is accepted, stored, and used to boost that block's chain weight. By repeatedly injecting certs for a block on a shorter adversarial fork that the node has already received, the attacker can make that fork's `totalWeight` exceed the canonical chain's weight, causing the honest node to roll back and adopt the adversarial chain. This is a direct bypass of Peras certificate validation and maps to the **Critical** impact category: *bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain selection manipulation*.

---

### Likelihood Explanation

The Peras cert diffusion mini-protocol is wired up in `mkHandlers` for every node-to-node connection without a feature-flag guard. Any peer that can establish a node-to-node connection — which requires no privileged keys — can send `PerasCert` messages. The attacker only needs to have previously diffused a candidate block to the target node (via the normal BlockFetch protocol) before sending the boosting certificate.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with genuine cryptographic and structural validation before the Peras cert diffusion mini-protocol is active in any production deployment. At minimum, gate the cert diffusion handler behind the same feature flag that controls Peras activation, so that nodes with Peras disabled cannot receive and process certificates at all. The existing `PerasCertValidationError` exception path in `processCerts` is already in place to reject invalid certs and disconnect the offending peer — it simply needs a real validator to call.

---

### Proof of Concept

1. Attacker connects to an honest node as a standard node-to-node peer.
2. Attacker diffuses a candidate block `B` (on a shorter fork) to the target node via BlockFetch; the node stores `B` in its `VolatileDB`.
3. Attacker sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = blockPoint B }` via the Peras cert diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
5. `ChainDB.addPerasCertAsync` is called; `chainSelSync` adds the cert to `cdbPerasCertDB` and calls `chainSelectionForBlock` for `B`.
6. `preferAnchoredCandidate` computes the candidate's `totalWeight` as `blockNo(B) + perasWeight(mkPerasParams)`. If this exceeds the canonical chain's weight, the node switches to the adversarial fork.
7. Steps 3–6 can be repeated with additional certs (for the same or different blocks) to accumulate further weight boost.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-210)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
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
