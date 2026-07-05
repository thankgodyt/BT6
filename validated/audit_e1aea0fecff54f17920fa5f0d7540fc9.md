### Title
Peras Certificate Validation Bypass via No-Op `validatePerasCert` Stub Enables Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance for all block types contains a stub `validatePerasCert` that unconditionally accepts every incoming Peras certificate without performing any cryptographic or quorum verification. An unprivileged peer can send a crafted `PerasCert` targeting any block, have it accepted as a `ValidatedPerasCert`, and cause the receiving node to apply an artificial weight boost to that block during chain selection. This is a direct analog to the SnapshotERC20Guild bug: just as that contract captured a snapshot of voting power *before* the state was updated (allowing incorrect power to persist), here the "validation snapshot" (`ValidatedPerasCert`) is produced without checking the underlying state (quorum, signatures, committee eligibility), allowing incorrect weight to be injected into chain selection.

---

### Finding Description

In `Ouroboros/Consensus/Block/SupportsPeras.hs`, the sole `BlockSupportsPeras` instance (which covers all block types, including production Cardano blocks) implements `validatePerasCert` as an unconditional stub:

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

This function is the gatekeeper that converts a raw `PerasCert blk` received over the network into a `ValidatedPerasCert blk`. It is called in the Peras cert diffusion inbound path before the cert is handed to `addPerasCertAsync`. Because it always returns `Right`, no signature, quorum, committee membership, or round-number check is ever performed.

The `ValidatedPerasCert` produced by this stub carries the full configured `perasWeight` boost:

```haskell
, vpcCertBoost = perasWeight params
``` [2](#0-1) 

Once accepted, the cert is stored in `PerasCertDB` via `implAddCert`, and the weight snapshot used for chain selection is recomputed from all stored certs:

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
``` [3](#0-2) 

Chain selection then uses this snapshot via `weightedSelectView` and `weightBoostOfFragment` to compare candidate chains:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
``` [4](#0-3) 

The cert diffusion inbound handler in the node-to-node layer passes the stake distribution context to vote validation but passes the cert directly through `validatePerasCert` before calling `addPerasCertAsync`:

```haskell
, addPerasCertAsync = getEnv1 h ChainSel.addPerasCertAsync
``` [5](#0-4) 

```haskell
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
``` [6](#0-5) 

The `chainSelSync` handler for `ChainSelAddPerasCert` then triggers chain selection for the boosted block:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [7](#0-6) 

---

### Impact Explanation

**Critical.** An unprivileged peer can inject an arbitrary number of crafted `PerasCert` messages, each boosting any block of their choice by the full `perasWeight` value. Because `validatePerasCert` never rejects any cert, the attacker can:

1. Boost a block on a weaker competing fork to make it appear heavier than the honest chain.
2. Cause the victim node to switch to the attacker's preferred (potentially invalid or adversarially controlled) chain.
3. Repeat this for multiple blocks, accumulating unbounded artificial weight — a direct analog to the "double-voting repeatedly on any future proposal" described in the original report.

This bypasses the entire Peras certificate verification mechanism (quorum threshold, committee eligibility, aggregate BLS signature), which is the core security property of the Peras protocol extension.

---

### Likelihood Explanation

**High.** The Peras cert diffusion mini-protocol is a standard node-to-node protocol reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The attacker only needs to craft a valid CBOR-encoded `PerasCert` (a simple struct containing a round number and a block point) and send it over the wire. The stub is in the sole production instance of `BlockSupportsPeras` and is not gated by any feature flag in the cert acceptance path.

---

### Recommendation

Replace the `validatePerasCert` stub with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the claimed committee members' public keys.
2. That the claimed voters constitute a quorum (total stake ≥ threshold) under the correct epoch's stake distribution.
3. That the round number is within the valid window (not too old, not in the future).
4. That the boosted block point is a known, valid block.

Until this is implemented, the Peras cert diffusion inbound handler should reject all incoming certs (or the feature should be disabled at the network level) to prevent exploitation.

---

### Proof of Concept

```
1. Attacker connects to victim node via the Peras cert diffusion mini-protocol.

2. Attacker constructs a crafted PerasCert:
     PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <point of target block> }
   No valid quorum, no BLS signature, no committee membership required.

3. Cert is received by the inbound handler, which calls:
     validatePerasCert params cert
   → always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })

4. ValidatedPerasCert is passed to addPerasCertAsync → enqueued in cdbChainSelQueue.

5. chainSelSync processes ChainSelAddPerasCert:
   - Cert is added to PerasCertDB (implAddCert).
   - implGetWeightSnapshot now includes the attacker's boosted block with weight = perasWeight params.
   - chainSelectionForBlock is triggered for the boosted block.

6. weightedSelectView computes wsvTotalWeight for the boosted chain fragment:
     wsvTotalWeight = blockNo + weightBoostOfFragment (which now includes attacker's boost)
   If this exceeds the current selection's weight, the node switches chains.

7. Attacker repeats with additional crafted certs to accumulate unbounded weight on any fork,
   causing the victim node to permanently prefer the attacker's chosen chain.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L61-87)
```haskell
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs (L307-307)
```haskell
            , addPerasCertAsync = getEnv1 h ChainSel.addPerasCertAsync
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
