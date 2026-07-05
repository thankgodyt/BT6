### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Fraudulent Chain-Selection Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a stub `validatePerasCert` that always returns `Right` (success) for any certificate, regardless of content. This stub is wired directly into the live inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can therefore send a crafted `PerasCert` naming any block as the boosted target; the certificate passes "validation", is stored in the `PerasCertDB`, and immediately triggers chain selection with the fraudulent weight boost applied. Because Peras weight is additive to block number in `wsvTotalWeight`, a sufficiently large boost can cause the honest node to abandon its canonical chain in favour of a shorter, attacker-controlled fork.

---

### Finding Description

**Root cause — always-`Right` certificate validator**

The default `BlockSupportsPeras` instance, which is the only instance in the codebase, contains:

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

No signature, committee membership, epoch-nonce binding, or round-number monotonicity check is performed. Every certificate is unconditionally promoted to `ValidatedPerasCert` and assigned the full configured `perasWeight`.

**Wiring into the live inbound pipeline**

`makePerasCertPoolWriterFromChainDB` — the production writer used when the node receives certificates from peers — passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every new certificate; if all pass (they always do), each is timestamped and forwarded to `addPerasCertAsync`: [3](#0-2) 

**Chain-selection consequence**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: the certificate is stored in `PerasCertDB`, and if the boosted block is in the `VolatileDB`, `chainSelectionForBlock` is called immediately: [4](#0-3) 

Chain selection uses `preferAnchoredCandidate`, which — when the `PerasWeightSnapshot` is non-empty — compares fragments by `wsvTotalWeight = blockNo + weightBoost`: [5](#0-4) 

The fraudulent certificate's boost is included in `weightBoostOfFragment` via the `PerasWeightSnapshot`, directly inflating the total weight of any chain containing the attacker-chosen block: [6](#0-5) 

---

### Impact Explanation

**Impact: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

A malicious peer constructs a `PerasCert` with `pcCertBoostedBlock` pointing to any block on a minority fork. Because `validatePerasCert` never rejects anything, the certificate is accepted, stored, and its boost is applied to chain selection. If the attacker-chosen block is in the node's `VolatileDB` (i.e., the node has already downloaded the fork), the node may immediately switch to that fork. The Peras weight boost is designed to be large enough to override the longest-chain rule; a single fraudulent certificate can therefore cause a permanent chain switch to a shorter, adversary-controlled fork, breaking the Common Prefix property for the affected node.

---

### Likelihood Explanation

**Likelihood: Medium.** The Peras object-diffusion mini-protocol is reachable by any peer that can establish a node-to-node connection — no stake, no keys, no privileged access required. The attacker only needs to know the hash of a block already present in the target node's `VolatileDB` (obtainable via ChainSync). The `PerasCert` wire format is simple (round number + block point), so crafting a valid-looking certificate is trivial. The only limiting factor is that Peras is not yet activated on mainnet; however, the code is present and wired in production builds, so any testnet or pre-production deployment is immediately exploitable.

---

### Recommendation

Replace the stub with a real implementation that verifies:

1. **Committee membership and signature** — the certificate must carry a valid aggregate signature from a quorum of the elected Peras committee for the claimed round, verified against the epoch nonce and stake distribution.
2. **Round-number monotonicity** — the certificate's round number must be strictly greater than the last accepted certificate round (analogous to nonce tracking in the external report).
3. **Epoch-nonce binding** — the certificate must be bound to the correct epoch nonce (`praosStatePreviousEpochNonce`) to prevent cross-epoch replay.

Until the real implementation is ready, the stub should at minimum **reject all certificates** (return `Left PerasValidationErr`) rather than accept all of them, so that the attack surface is closed in pre-production deployments.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to an honest node as a normal peer.
2. Via ChainSync, attacker learns hash `H` of a block on a minority fork that the honest node has in its `VolatileDB`.
3. Attacker sends a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slot H }` over the Peras cert object-diffusion sub-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
5. `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` finds block `H` in `VolatileDB`, calls `chainSelectionForBlock`.
7. `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork containing `H`; the fraudulent boost makes it exceed the honest chain's total weight.
8. The node switches to the minority fork.

**Key files and lines:**

| Step | File | Lines |
|---|---|---|
| Stub validator | `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` | 350–358 |
| Inbound pipeline wiring | `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` | 118–137 |
| `processCerts` accepts all | same file | 164–173 |
| ChainSel triggered | `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs` | 483–532 |
| Weight drives fork switch | `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs` | 58–87 |

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-268)
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
