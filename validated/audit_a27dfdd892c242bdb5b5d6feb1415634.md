### Title
Stub `validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates, Enabling Chain-Selection Manipulation by Any Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally accepts every inbound certificate without performing any cryptographic or quorum validation. Any unprivileged peer can send a crafted `PerasCert` over the `PerasCertDiffusion` mini-protocol, have it accepted into the `PerasCertDB`, and cause the node to re-run chain selection with an artificially inflated `PerasWeightSnapshot`. This can make the node prefer a non-canonical fork or permanently misplace the immutability boundary.

---

### Finding Description

The `BlockSupportsPeras` instance for all block types is a degenerate stub (marked with a TODO referencing issue #73) that always returns `Right` from `validatePerasCert`:

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

No signature check, no committee membership check, and no quorum verification is performed. The `vpcCertBoost` is simply set to `perasWeight params` — the configured boost weight — for every certificate, regardless of its origin or content.

This stub is wired directly into the production inbound network path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- stub: always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

This writer is registered as the inbound handler for the `PerasCertDiffusion` mini-protocol in `NodeToNode.hs`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

Once a certificate passes the stub validation and is added to the `PerasCertDB`, `chainSelSync` is triggered. It calls `chainSelectionForBlock` for the boosted block, which re-evaluates chain selection using the updated `PerasWeightSnapshot`: [4](#0-3) 

Chain selection compares fragments by `wsvTotalWeight`, which sums block count and weight boost from the snapshot:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

The immutability boundary is also computed from the same snapshot via `takeVolatileSuffix`, which uses `totalWeightOfFragment` against the security parameter `k`: [6](#0-5) 

---

### Impact Explanation

**Critical / High.** An unprivileged peer can:

1. **Force a chain switch to a non-canonical fork**: By sending a crafted `PerasCert` that boosts a block on an adversarial fork, the attacker inflates that fork's `wsvTotalWeight` above the honest chain's weight, causing `preferCandidate` to return `ShouldSwitch`. The node adopts the adversarial chain.

2. **Misplace the immutability boundary**: `takeVolatileSuffix` uses the weight snapshot to determine which blocks are buried under weight `k`. A fake certificate boosting a block on the current chain can push additional blocks past the immutability threshold, preventing legitimate rollbacks that would otherwise be valid.

3. **Bypass Peras certificate/vote verification entirely**: The `validatePerasCert` stub means the Peras certificate acceptance mechanism provides zero security — any peer can inject certificates for any block at any round.

---

### Likelihood Explanation

**High.** The `PerasCertDiffusion` mini-protocol is an open, unauthenticated peer-to-peer channel. Any node that connects to a victim node can send a `PerasCert` message. The stub validation always returns `Right`, so there is no barrier to acceptance. The attack requires only a network connection and knowledge of a target block's `Point` (slot + hash), both of which are publicly observable from the chain.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
- Verifies the certificate's cryptographic signature(s) against the known committee public keys for the given round.
- Checks that the signing committee members were legitimately elected (VRF-based sortition against the epoch's stake snapshot).
- Verifies that the aggregate stake of the signers meets the quorum threshold defined in `PerasCfg`.
- Rejects certificates whose `pcCertBoostedBlock` does not correspond to a known, valid block.

Until real validation is in place, the `PerasCertDiffusion` inbound handler should be disabled or gated behind a feature flag that is off by default, consistent with the existing note that "if Peras is disabled (which is the default), there is no observable difference."

---

### Proof of Concept

**Analog to the external report**: The external report shows that `get_cost_amount` uses `dex::get_spot_price` — an instantaneous pool-reserve ratio — without time-weighting, so an attacker can manipulate the price by depositing into the pool. Here, `validatePerasCert` uses the instantaneous `perasWeight params` value without any cryptographic check, so an attacker can inject a certificate for any block by simply sending a `PerasCert` message over the wire.

**Attack sequence (private testnet)**:

1. Attacker connects to victim node via the `PerasCertDiffusion` mini-protocol.
2. Attacker observes the tip of an adversarial fork (block hash `H`, slot `S`).
3. Attacker sends `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint S H }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
5. Certificate is added to `PerasCertDB`; `addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event.
6. `chainSelSync` runs: the adversarial fork's `PerasWeightSnapshot` now includes a boost of `perasWeight mkPerasParams` for block `H`.
7. `preferCandidate` compares `wsvTotalWeight` of the honest chain vs. the boosted adversarial fork; if the boost exceeds the honest chain's lead, `ShouldSwitch` is returned.
8. The victim node switches to the adversarial chain. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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
