### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Submitted Peras Certificate, Enabling Unauthorized Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every certificate it receives. Because the Peras certificate diffusion miniprotocol (`hPerasCertDiffusionClient`) is open to any unprivileged NTN peer, an attacker can inject a crafted `PerasCert` that boosts an arbitrary block in the VolatileDB. The injected certificate bypasses all validation, is stored in the `PerasCertDB`, and immediately triggers chain selection with the fraudulent weight boost, potentially causing the node to switch to a fork it would not otherwise prefer.

---

### Finding Description

**Root cause — stub validator always accepts:**

The `BlockSupportsPeras` instance for all `StandardHash blk` types implements `validatePerasCert` as an unconditional `Right`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [1](#0-0) 

No signature, no committee membership check, no round-number bounds check — every certificate is accepted.

**Attacker-reachable entry path — NTN miniprotocol:**

The `hPerasCertDiffusionClient` handler in the node-to-node handler record wires `objectDiffusionInbound` directly to `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with the stub validator:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

`processCerts` calls `validatePerasCert mkPerasParams` on each inbound certificate. Because the stub always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection side-effect:**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: the certificate is stored in `PerasCertDB`, the `PerasWeightSnapshot` is updated, and `chainSelectionForBlock` is called for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection now uses `preferAnchoredCandidate` with the updated snapshot. The total weight of a fragment is `wsvBlockNo + wsvWeightBoost`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

A fork block that was previously lighter than the current chain tip can become heavier after the fraudulent boost, causing `preferAnchoredCandidate` to return `ShouldSwitch` and the node to roll back to the fork. [6](#0-5) 

**Contrast with vote path (not vulnerable):**

The vote diffusion handler intentionally passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution, which causes `validatePerasVote` to reject all votes (a voter not in the empty map returns `Left`). The certificate path has no equivalent guard. [7](#0-6) 

---

### Impact Explanation

An unprivileged NTN peer can craft a `PerasCert` naming any block hash present in the target node's VolatileDB (observable via ChainSync) and submit it via the Peras certificate diffusion miniprotocol. The stub validator accepts it unconditionally. The resulting weight boost can make a previously non-preferred fork appear heavier than the current selection, causing the node to roll back and adopt the attacker-chosen fork. This is a **chain selection integrity failure**: an honest node is made to prefer a non-canonical chain beyond the intended security assumptions, without the attacker needing any stake, keys, or operator access.

Impact category: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

---

### Likelihood Explanation

Any peer that can establish a NTN connection (i.e., any node on the network) can trigger this. The attacker needs only to observe a block hash in the VolatileDB via ChainSync (a normal, unauthenticated operation) and send a single crafted certificate message. No cryptographic material, stake, or privileged access is required. The Peras cert diffusion protocol handler is unconditionally registered in the NTN handler record.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies certificate authenticity (committee membership, cryptographic signature, round-number validity) before accepting any certificate from an external peer. Until real validation is implemented, the `hPerasCertDiffusionClient` handler should reject all inbound certificates from external peers (analogous to how the vote handler uses `PerasVoteStakeDistr mempty` to reject all votes), preventing any external actor from influencing the `PerasCertDB` and chain selection weights.

---

### Proof of Concept

1. Connect to a target node via the NTN protocol.
2. Use ChainSync to observe a block hash `H` on a fork in the node's VolatileDB (a block the node received but did not select).
3. Construct a `PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <point with hash H> }`.
4. Send it via the Peras certificate diffusion miniprotocol (`MsgReplyObjects [cert]` in response to a `MsgRequestObjects` from the node's inbound handler).
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{..}` (stub always accepts).
6. `ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for block `H`.
7. `preferAnchoredCandidate` now computes the fork's weight as `blockNo(H) + perasWeight(params)`, which may exceed the current chain's weight, causing the node to roll back and adopt the fork.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-410)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
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
