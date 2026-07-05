### Title
Unconditional Peras Certificate Acceptance Bypasses Chain Selection Authorization — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate received from an untrusted NTN peer. Because accepted certificates are stored in the `PerasCertDB` and used to boost block weights in chain selection, any unprivileged peer can inject a crafted `PerasCert` that causes the node to prefer a non-canonical chain over the honest chain.

---

### Finding Description

**Root cause — stub validation always accepts:**

The `BlockSupportsPeras` instance in `SupportsPeras.hs` (lines 318–389) is explicitly marked as a temporary degenerate instance. Its `validatePerasCert` implementation performs zero cryptographic or authorization checks and unconditionally returns `Right`:

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

**Entry point — NTN peer cert diffusion is wired up:**

The production NTN handler in `NodeToNode.hs` registers `makePerasCertPoolWriterFromChainDB` as the inbound handler for the Peras certificate diffusion mini-protocol. This handler is reachable from any untrusted peer that negotiates the protocol:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

**Processing path — stub is called directly:**

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. Because the stub always returns `Right`, every certificate in the batch passes:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` applies `validateCert <$> certsNotAlreadyInDb` and, finding no errors, adds every certificate to the `PerasCertDB` via `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain selection impact — accepted cert triggers re-selection:**

`chainSelSync` processes the newly added certificate. It reads the `PerasWeightSnapshot`, looks up the boosted block in the `VolatileDB`, and calls `chainSelectionForBlock` for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

`preferAnchoredCandidate` then uses the weight snapshot to compare chains. When Peras is active (i.e., the weight snapshot is non-empty), it computes `weightedSelectView` over the suffix after the intersection, and the crafted certificate's boost (`perasWeight params`) is added to the attacker's preferred block:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
        case preferCandidate
          (projectChainOrderConfig cfg)
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix) of
``` [6](#0-5) 

The `wsvTotalWeight` comparison means a boosted fork block can exceed the honest chain's weight, causing the node to switch: [7](#0-6) 

---

### Impact Explanation

An unprivileged NTN peer can send a crafted `PerasCert` referencing any block already in the node's `VolatileDB`. Because `validatePerasCert` is a stub that never rejects, the certificate is accepted, stored, and used to boost that block's weight in chain selection. If the boosted block is on a fork, the node will switch to the non-canonical chain. This is a **High** impact chain selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Ouroboros.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol handler is registered unconditionally in the production NTN handler. Any peer that can establish an NTN connection and negotiate the protocol can send crafted certificates. The stub is explicitly marked TODO and is the universal fallback instance used for all block types, meaning no block type has real validation. The boosted block only needs to be present in the node's `VolatileDB`, which is trivially achievable by first sending the block via BlockFetch.

---

### Recommendation

1. **Immediate**: Disable the Peras certificate diffusion mini-protocol (or gate it behind a feature flag) until `validatePerasCert` is fully implemented with cryptographic verification.
2. **Long-term**: Implement `validatePerasCert` to verify the aggregate BLS/KES signature over the certificate, check that the round number is within the valid range, verify the boosted block is on a valid chain, and confirm the certificate has sufficient stake to reach quorum per the committee selection rules.
3. Track the referenced issue: `https://github.com/tweag/cardano-peras/issues/120`.

---

### Proof of Concept

1. Establish an NTN connection to a target node and negotiate the Peras certificate diffusion protocol.
2. Identify a block `B` on a fork that is present in the target node's `VolatileDB` (or send it via BlockFetch first).
3. Craft a `PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B) }` for any round `R` not already in the node's `PerasCertDB`.
4. Send the certificate via the `PerasCertDiffusion` mini-protocol.
5. `validatePerasCert` returns `Right` unconditionally; the certificate is added to the `PerasCertDB`.
6. `chainSelSync` triggers `chainSelectionForBlock` for block `B`; `preferAnchoredCandidate` now computes `wsvTotalWeight` including the boost from the crafted certificate.
7. If `blockNo(B) + perasWeight >= blockNo(honest_tip)`, the node switches to the fork containing `B`, diverging from the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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
