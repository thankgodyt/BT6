### Title
Peras Certificate Validation Is a No-Op Stub, Allowing Any Peer to Inject Arbitrary Weight Boosts into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation for all block types unconditionally returns `Right` without performing any cryptographic or semantic checks. An unprivileged peer can send a crafted `PerasCert` boosting any block in the VolatileDB, causing the receiving node to assign that block an inflated `PerasWeight` and potentially switch to a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines a `validatePerasCert` method that is supposed to authenticate a Peras certificate before it is accepted into the `PerasCertDB` and used to influence chain selection. The current universal instance, which is the only instance in the codebase, is an acknowledged stub:

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

Every `PerasCert` received from any peer is unconditionally wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost. No signature, quorum proof, round validity, or boosted-block eligibility check is performed.

The inbound certificate diffusion path in `makePerasCertPoolWriterFromChainDB` calls `processCerts` with this stub as the validator:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` rejects a batch only if `validateCert` returns `Left`; since it never does, every inbound cert passes and is forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

Inside `chainSelSync`, the accepted cert is stored in `PerasCertDB` and, if the boosted block exists in the VolatileDB, `chainSelectionForBlock` is immediately triggered for it:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection reads the `PerasWeightSnapshot` from `PerasCertDB` and computes `wsvTotalWeight = BlockNo + wsvWeightBoost` for each candidate fragment: [5](#0-4) 

The weight boost is the sum of `weightBoostOfPoint` for every block in the fragment that appears in the snapshot: [6](#0-5) 

Because `implGetWeightSnapshot` derives the snapshot directly from every cert stored in `PerasCertDB` without re-validating them, a fake cert's boost is indistinguishable from a legitimate one: [7](#0-6) 

The `implAddCert` function itself also carries the same TODO and performs no content validation beyond a duplicate-round-number check: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that names any block in the node's VolatileDB as the boosted block. That block's fork immediately receives a `perasWeight` boost in chain selection. If the fork's `wsvTotalWeight` (block count + boost) exceeds the current chain's total weight, `preferAnchoredCandidate` returns `ShouldSwitch` and the node rolls back to the fork. This constitutes:

- **Bypass of Peras certificate/vote verification checks** — the certificate is accepted without any proof of quorum, signature, or round eligibility.
- **Chain selection manipulation** — an honest node can be made to prefer a non-canonical or adversarially-chosen fork, violating the Ouroboros chain-selection invariant.

---

### Likelihood Explanation

The object diffusion mini-protocol for Peras certificates is reachable by any connected peer. No stake, key material, or privileged access is required to send a `PerasCert` message. The only guard is the duplicate-round-number check in `implAddCert`, which an attacker trivially avoids by using a fresh round number. The attack is deterministic and requires a single network message.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that verifies:
1. The certificate's aggregate BLS/cryptographic signature against the claimed committee.
2. That the total stake of the signers meets the quorum threshold.
3. That the boosted block's slot falls within the valid Peras round window.
4. That the round number is consistent with the current chain tip.

Until real validation is in place, inbound certificates from peers should be rejected entirely (or the Peras weight path should be disabled) to prevent chain selection manipulation.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node as a normal peer.
2. Attacker observes a block `B` on a competing fork in the VolatileDB (e.g., via ChainSync headers).
3. Attacker constructs `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = pointOf(B) }` — no signature or quorum proof needed.
4. Attacker sends the cert via the Peras certificate object diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
6. `addPerasCertAsync` enqueues the cert; `chainSelSync` stores it in `PerasCertDB`.
7. `implGetWeightSnapshot` now returns a snapshot containing `pointOf(B) → perasWeight`.
8. `chainSelectionForBlock` is called for `B`; `weightBoostOfFragment` adds `perasWeight` to the fork's total weight.
9. If `BlockNo(B_fork_tip) + perasWeight > BlockNo(current_tip)`, `preferAnchoredCandidate` returns `ShouldSwitch` and the node adopts the adversarial fork. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
