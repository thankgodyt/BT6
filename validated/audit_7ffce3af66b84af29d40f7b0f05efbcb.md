### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance is a stub that always returns `Right` regardless of certificate content. When Peras is enabled via feature flags, any unprivileged peer can send a crafted `PerasCert` through the ObjectDiffusion mini-protocol. The certificate is accepted without any cryptographic verification and is immediately applied to chain selection, boosting the weight of an attacker-chosen block and potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation in `BlockSupportsPeras`:**

The `BlockSupportsPeras` instance for all block types contains a placeholder `validatePerasCert` that unconditionally accepts every certificate:

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

The comment explicitly marks this as a TODO stub. No signature, quorum proof, committee membership, or round-number plausibility check is performed.

**Entry path — ObjectDiffusion inbound handler:**

`mkPerasCertObjectPoolWriter` wires this stub directly into the inbound certificate processing pipeline:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validatePerasCert` for every certificate received from a peer. Because the stub always returns `Right`, every certificate passes: [3](#0-2) 

**Immediate chain-selection effect — no delay, no stability requirement:**

Once accepted, the certificate is added to the `PerasCertDB` and `addPerasCertAsync` is called, which immediately triggers `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection compares fragments by `wsvTotalWeight`, which sums `BlockNo` and `wsvWeightBoost`. A crafted certificate targeting a block on a competing fork inflates that fork's weight immediately, with no stability window, no epoch-boundary delay, and no rollback protection: [5](#0-4) 

The `PerasWeight` boost is taken directly from `perasWeight mkPerasParams` (hardcoded default `15`), so every accepted certificate adds a fixed boost of 15 to the targeted block's chain weight, regardless of the actual stake behind the certificate. [6](#0-5) 

**Analogy to the external report:**

The external report describes a pool owner who can change the `protocolFeePercent` parameter at any time without a timelock, front-running swaps to extract value. The analog here is that any peer can inject a Peras certificate at any time without a validity check, immediately shifting chain-selection weight without any delay or stability requirement. In both cases a parameter/state change takes effect instantly with no guard, and the attacker controls the timing and magnitude.

---

### Impact Explanation

When Peras is enabled via `rnFeatureFlags`, an unprivileged peer can:

1. Send a crafted `PerasCert` naming any block in the volatile DB as the boosted block.
2. The certificate bypasses all cryptographic checks (`validatePerasCert` always returns `Right`).
3. The certificate is stored in `PerasCertDB` and the `PerasWeightSnapshot` is updated immediately.
4. `chainSelectionForBlock` is triggered for the boosted block; if the boosted block is on a competing fork, the node's `wsvTotalWeight` comparison may now favour that fork.
5. The node switches to the non-canonical chain, diverging from honest peers.

This satisfies the **Critical** allowed impact: bypass of Peras certificate validation enabling unauthorized certificate acceptance, and **High** allowed impact: chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

Peras is gated behind `rnFeatureFlags` and is disabled by default. However, the production code path is fully wired: the ObjectDiffusion inbound handler, `processCerts`, `PerasCertDB`, and `chainSelectionForBlock` are all live. Any operator who enables Peras exposes their node to this attack immediately. The attack requires only a network connection and the ability to send a single well-formed `PerasCert` message — no stake, no keys, no privileged access.

---

### Recommendation

1. **Do not enable Peras in production** until `validatePerasCert` performs real cryptographic verification (committee membership proof, BLS/aggregate signature, round-number bounds, boosted-block plausibility).
2. Track issue [#120](https://github.com/tweag/cardano-peras/issues/120) to completion before any production rollout.
3. Consider adding a compile-time or runtime guard that prevents `mkPerasCertObjectPoolWriter` from being instantiated when `validatePerasCert` is still the stub, so the feature flag cannot accidentally activate an unvalidated pipeline.
4. Apply a stability/delay requirement analogous to the `shelleyAfterVoting >= k` guard used for era transitions: certificates should only influence chain selection once the boosted block is sufficiently deep, preventing immediate weight manipulation.

---

### Proof of Concept

```
1. Start a node with Peras enabled via rnFeatureFlags.
2. Connect to the node as an unprivileged peer via the ObjectDiffusion mini-protocol.
3. Craft a PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <hash of a block on a competing fork> }.
4. Send the certificate to the node.
5. processCerts calls (validatePerasCert mkPerasParams cert) → Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }.
6. addPerasCertAsync triggers chainSelectionForBlock for the boosted block.
7. wsvTotalWeight of the competing fork increases by 15; if this exceeds the current selection's weight, the node switches forks.
8. The node now tracks a non-canonical chain, diverging from honest peers.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L163-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L169-172)
```haskell
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
```
