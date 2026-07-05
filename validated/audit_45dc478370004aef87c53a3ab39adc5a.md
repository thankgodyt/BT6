### Title
Stub `validatePerasCert` Unconditionally Accepts All Peer-Supplied Peras Certificates, Enabling Chain-Selection Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural checks. Because this function sits directly on the NTN Peras certificate diffusion inbound path, any unprivileged peer can inject arbitrary `PerasCert` objects that are accepted without validation, added to the `PerasCertDB`, and used to boost arbitrary blocks in chain selection via the `PerasWeightSnapshot`. This is the direct analog of the missing `onlyAdmin` modifier in the external report: just as any caller could invoke `update()` to inflate earnings, any peer can invoke the cert diffusion protocol to inflate the chain-selection weight of a chosen block.

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

The universal instance (applied to every block type) reads:

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

No signature, round-number, boosted-block, or committee-membership check is performed. Every certificate, regardless of content, is wrapped in `Right` and stamped with the configured boost weight.

**Attacker-controlled entry path:**

The NTN handler wires the cert diffusion inbound mini-protocol directly to `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the validator: [2](#0-1) [3](#0-2) 

`processCerts` calls `validateCert` on each received certificate and, because `validatePerasCert` always returns `Right`, every cert passes: [4](#0-3) 

The accepted cert is then forwarded to `ChainDB.addPerasCertAsync`, which queues it for `chainSelSync`: [5](#0-4) 

**Chain-selection impact:**

`chainSelSync` adds the cert to the `PerasCertDB`, which updates the `PerasWeightSnapshot`. Chain selection then uses this snapshot to compute the total weight of every candidate fragment: [6](#0-5) [7](#0-6) 

A crafted cert that names a block on a competing fork as `pcCertBoostedBlock` inflates that fork's total weight, potentially causing the honest node to switch away from the canonical chain.

### Impact Explanation

**High — chain selection bug.** An unprivileged NTN peer can inject a `PerasCert` naming any `Point blk` as the boosted block. The resulting `PerasWeightSnapshot` entry adds `perasWeight params` to every candidate fragment that contains that point. If the attacker targets a block on a minority fork, the honest node may compute that fork as heavier than the canonical chain and switch to it, constituting a non-canonical chain preference beyond the intended Peras security assumptions. The `takeVolatileSuffix` function also uses the same weight snapshot to determine the immutability boundary, so a sufficiently large injected boost can additionally shrink the volatile window and cause premature immutability of attacker-chosen blocks. [8](#0-7) 

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is registered unconditionally in the NTN handler for all peers: [9](#0-8) 

Any peer that can establish an NTN connection can send crafted certificates. No stake, key, or privileged credential is required. The attack requires only knowledge of a target block's `Point` (slot + hash), which is public information available from the ChainSync protocol. The exploit is a single crafted protocol message.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS/committee signature against the registered committee for the claimed round.
2. That `pcCertBoostedBlock` refers to a block that actually exists in the volatile or immutable DB.
3. That `pcCertRound` falls within the valid range relative to the current slot.
4. That the claimed voters collectively hold sufficient stake to meet the quorum threshold.

Until the real implementation is in place, the stub should be replaced with a function that always returns `Left PerasValidationErr` (reject all), rather than `Right` (accept all), so that the cert diffusion path is safely inert. The existing `TODO` at `https://github.com/tweag/cardano-peras/issues/120` tracks this work and should be treated as a security-critical blocker before Peras is enabled on any network where the cert diffusion mini-protocol is active.

### Proof of Concept

1. Attacker establishes an NTN connection to an honest node running a build where Peras weight is non-zero.
2. Attacker observes via ChainSync that the honest node's current chain tip is at block `B_honest` (slot `s`, hash `h`).
3. Attacker has a competing fork whose tip is at block `B_fork` with block number one less than `B_honest` (normally not preferred).
4. Attacker crafts `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s_fork h_fork }` where `(s_fork, h_fork)` is a block on the competing fork.
5. Attacker sends this cert via the `PerasCertDiffusion` mini-protocol.
6. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = W }` for some `W > 0`.
7. The cert is added to `PerasCertDB`; `PerasWeightSnapshot` now maps `BlockPoint s_fork h_fork` to weight `W`.
8. `chainSelSync` re-runs chain selection; the fork's total weight is now `blockNo(B_fork) + W`, which exceeds `blockNo(B_honest) + 0` if `W > blockNo(B_honest) - blockNo(B_fork)`.
9. The honest node switches to the attacker's fork, accepting a non-canonical chain.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L233-241)
```haskell
  , hPerasCertDiffusionClient ::
      NodeToNodeVersion ->
      ControlMessageSTM m ->
      ConnectionId addr ->
      PerasCertDiffusionInboundPipelined blk m ()
  , hPerasCertDiffusionServer ::
      NodeToNodeVersion ->
      ConnectionId addr ->
      PerasCertDiffusionOutbound blk m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
