### Title
`validatePerasCert` Always Returns `Right` Without Performing Any Validation, Allowing Unprivileged Peers to Inject Arbitrary Peras Weight Boosts into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` with a fixed boost value (`perasWeight params`) for every certificate it receives, regardless of whether the certificate is cryptographically valid or was issued by a legitimate committee member. This is the function called in the production inbound-certificate processing path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject arbitrary Peras certificates that boost any block of their choosing, directly manipulating chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must accept or reject a `PerasCert` received from a peer before it is stored and used to influence chain selection. The default instance, which is the only instance in the codebase and is used in production, is:

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

This unconditionally returns `Right` — no signature check, no committee-membership check, no round-number sanity check — and always assigns the full configured `perasWeight params` boost. [1](#0-0) 

This function is wired directly into the production inbound-certificate writer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate received from a peer; if all pass (which they always do), each is timestamped and added to the `PerasCertDB` via `addPerasCertAsync`, which triggers chain selection for the boosted block. [3](#0-2) 

Once stored, the certificate's boost is included in `weightBoostOfFragment`, which feeds `wsvTotalWeight`, which is the primary comparator in `preferCandidate` for Peras-enabled chain selection:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

```haskell
preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch ...
``` [5](#0-4) 

**Analog to the external report:** Just as `getRewards` always deducts `REFERRER_FEE` regardless of whether any referrers exist (a fixed value applied unconditionally), `validatePerasCert` always applies the fixed `perasWeight params` boost regardless of whether the certificate is legitimate. In both cases a fixed quantity is unconditionally applied when the condition that justifies it (referrer existence / valid certificate) may be absent.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` message targeting any block in the VolatileDB. Because `validatePerasCert` never rejects, the certificate is accepted, stored, and its boost is applied to chain selection. By boosting a block on a minority fork, the attacker can cause an honest node to prefer that fork over the canonical chain, constituting a **chain-selection manipulation** that lets an adversary make an honest node adopt a non-canonical or less-secure chain. This matches the "High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact tier, and also the "Critical — bypass of Peras certificate checks" tier.

---

### Likelihood Explanation

The Peras certificate mini-protocol (`ObjectDiffusion`) is a public network-facing interface. Any peer that can establish a connection can send `PerasCert` messages. No stake, key material, or privileged access is required. The attack is deterministic and requires only a single crafted message per target block.

---

### Recommendation

Implement actual cryptographic and committee-membership validation inside `validatePerasCert` before the Peras certificate mini-protocol is enabled on any network. At minimum:

1. Verify the certificate's cryptographic signature against the claimed committee member's key.
2. Verify the signer is a member of the Peras voting committee for the claimed round (using the stake snapshot).
3. Verify the round number is within an acceptable window relative to the current chain tip.
4. Reject certificates whose `pcCertBoostedBlock` does not correspond to a known block.

Until real validation is implemented, the production `makePerasCertPoolWriterFromChainDB` path should not be reachable from untrusted peers.

---

### Proof of Concept

1. Node A is running with Peras enabled and has block `B_fork` (a minority-fork block) in its VolatileDB.
2. Attacker peer connects to Node A via the Peras certificate mini-protocol.
3. Attacker sends `PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B_fork }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
5. Certificate is added to `PerasCertDB`; `addPerasCertAsync` triggers `chainSelSync` for `B_fork`.
6. `weightBoostOfFragment` now returns `perasWeight params` for any fragment containing `B_fork`.
7. `preferCandidate` compares `wsvTotalWeight` of the current chain vs. the fork; if the fork's block number plus boost exceeds the current chain's total weight, Node A switches to the fork. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L259-267)
```haskell
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
