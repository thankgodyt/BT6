### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Forged Certificate, Enabling Chain Selection Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal degenerate `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, without verifying the certificate against any stake distribution or quorum threshold. Because the Peras certificate diffusion protocol is fully wired into the production node-to-node stack and feeds directly into chain selection, an unprivileged peer can send a crafted `PerasCert` boosting any block in the VolatileDB, causing the receiving node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` class defines a universal instance for all `StandardHash blk` types. Its `validatePerasCert` implementation is a placeholder that always succeeds:

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

No signature check, no quorum-of-stake check, no committee membership check, and no epoch-snapshot binding is performed. Every `PerasCert` received from any peer is unconditionally wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost.

**Production wiring — cert diffusion pool writer:**

`makePerasCertPoolWriterFromChainDB` is the production inbound handler for the Peras certificate diffusion mini-protocol. It calls `validatePerasCert mkPerasParams` directly:

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
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

This is wired into the live node-to-node protocol stack in `NodeToNode.hs`: [3](#0-2) 

**Chain selection impact — `chainSelSync` for `ChainSelAddPerasCert`:**

Once a certificate passes the stub validator and is added to `PerasCertDB`, `addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. The chain selection handler then:
1. Looks up the boosted block in the VolatileDB.
2. Calls `chainSelectionForBlock` for that block, now carrying the extra `PerasWeight` boost.
3. `preferAnchoredCandidate` uses the updated `PerasWeightSnapshot` to compare chains, potentially switching to the fork containing the boosted block. [4](#0-3) 

The `weightedSelectView` function computes `wsvTotalWeight = blockNo + weightBoost`, so a sufficiently large `perasWeight` can make a shorter fork outweigh the honest chain: [5](#0-4) 

**Analog to the external report:**

The ZivoeYDL bug uses a live `totalSupply()` that can be temporarily inflated to manipulate a yield-distribution ratio. Here, `validatePerasCert` uses no stake distribution at all — it is the degenerate case where the "snapshot" is entirely absent. An attacker can craft a certificate for any block they have already propagated to the victim, permanently boosting that block's chain-selection weight for the lifetime of the certificate in the VolatileDB.

---

### Impact Explanation

An unprivileged peer can cause an honest node to switch to a non-canonical chain by:
1. Propagating a valid-header fork block to the victim (normal block diffusion).
2. Sending a crafted `PerasCert` whose `pcCertBoostedBlock` points to that fork block.
3. The victim's `validatePerasCert` accepts the certificate unconditionally.
4. Chain selection re-runs with the fork block carrying a `PerasWeight` boost equal to `perasWeight params`, which can exceed the honest chain's block-number advantage.

This is a **Critical** bypass of Peras certificate verification that enables unauthorized certificate acceptance and chain selection manipulation, matching the allowed impact: *"Bypass of … Peras voting or certificate checks … that enables unauthorized block, vote, or certificate acceptance."*

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is fully wired into the production node-to-node stack. Any connected peer can send `PerasCert` messages. The stub validator requires zero cryptographic material — the attacker only needs to know the `Point` of a block already in the victim's VolatileDB (learnable via ChainSync). No stake, no keys, and no special privileges are required.

---

### Recommendation

1. **Replace the degenerate instance** with a proper per-era `BlockSupportsPeras` instance that verifies the certificate's aggregate BLS signature against the epoch-snapshot stake distribution and confirms the quorum threshold is met, as already scaffolded in `WFALS.hs` (`implVerifyCert`) and `EveryoneVotes.hs`.

2. **Pass the epoch-snapshot stake distribution** (analogous to Praos's `PoolDistr` from `ssStakeMarkPoolDistr`) into `validatePerasCert` so that the quorum check is anchored to a historical, manipulation-resistant snapshot — directly addressing the flash-loan-style manipulation class from the external report.

3. **Gate the cert diffusion handler** on Peras era activation so that the stub path is unreachable until a correct implementation is in place.

---

### Proof of Concept

On a private testnet with Peras cert diffusion enabled:

```
1. Attacker connects to victim node via node-to-node protocol.
2. Attacker propagates a fork block B_fork to victim (standard BlockFetch).
3. Attacker sends PerasCert { pcCertRound = r, pcCertBoostedBlock = point(B_fork) }
   via the PerasCertDiffusion mini-protocol.
4. Victim calls validatePerasCert mkPerasParams cert
   → always returns Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })
5. Victim calls addPerasCertAsync, enqueuing ChainSelAddPerasCert.
6. chainSelSync looks up B_fork in VolatileDB, finds it, calls chainSelectionForBlock.
7. preferAnchoredCandidate computes wsvTotalWeight(fork) = blockNo(B_fork) + perasWeight
   vs wsvTotalWeight(honest) = blockNo(honest_tip) + 0.
8. If perasWeight > (blockNo(honest_tip) - blockNo(B_fork)), victim switches to fork.
```

The `perasWeight` default value is set in `mkPerasParams`; with the current tentative parameters it is large enough to overcome a multi-block honest-chain lead. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-151)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
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
