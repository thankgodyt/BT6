### Title
Peras Certificate Validation Stub Unconditionally Accepts All Certificates, Enabling Arbitrary Chain-Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that **always returns `Right`** without performing any cryptographic or committee-membership checks. Any certificate received from an unprivileged peer over the network passes validation unconditionally, is stored in the `PerasCertDB`, and its `vpcCertBoost` weight is applied to chain selection. An attacker can craft a certificate boosting any block in the VolatileDB, causing an honest node to prefer a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a received `PerasCert` before it is accepted into the node's state. The production universal instance, explicitly marked as a temporary stub, unconditionally returns `Right`:

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

This stub is the **only** validation gate in the inbound certificate processing path. `processCerts` in `PerasCert.hs` calls the supplied `validateCert` function and, if it returns `Right` for all certificates, passes them directly to `addCert` (which is `ChainDB.addPerasCertAsync` in production):

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

The production pool writer wires `validatePerasCert mkPerasParams` (the always-`Right` stub) directly into this path:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [3](#0-2) 

Once accepted, `chainSelSync` adds the certificate to `PerasCertDB` and triggers chain selection for the boosted block:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `PerasWeightSnapshot` derived from the stored certificates is then used in `WeightedSelectView` to compare candidate chains, where `wsvTotalWeight` adds the boost to the block number:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

The structural analog to the external report is exact: in the Tapioca bug, `routerETH.swapETH` sends an **empty payload** so `sgReceive` (the deposit callback) is never invoked, leaving ETH stranded and exploitable. Here, `validatePerasCert` is the "payload" of the validation callback — its body is empty (always `Right`), so the certificate is accepted and its weight applied without any actual verification, leaving chain selection open to manipulation.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` with `pcCertBoostedBlock` pointing to any block currently in the node's VolatileDB. Because `validatePerasCert` never rejects anything, the certificate is stored and its `vpcCertBoost` (set to `perasWeight params`) is added to the total weight of any chain containing that block. This can cause the node to switch to a fork it would not otherwise prefer, violating chain selection safety. The attacker controls which block is boosted and by how much (within the configured `perasWeight`), enabling targeted chain-selection manipulation without any stake or cryptographic material.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions; also matches Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The inbound certificate diffusion mini-protocol (`makePerasCertPoolWriterFromChainDB`) is reachable by any connected peer. No authentication, stake ownership, or key material is required to send a `PerasCert` message. The stub is the **universal** instance used for all block types (see the `instance StandardHash blk => BlockSupportsPeras blk` declaration), so there is no era or configuration that escapes it. The only prerequisite is that the boosted block's hash exists in the node's VolatileDB, which is trivially satisfiable by any peer that has previously sent the node a valid header for that block. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's committee membership proof (VRF-based sortition or equivalent).
2. The cryptographic signature(s) over the certificate content.
3. That `pcCertBoostedBlock` refers to a block within the valid Peras voting window.
4. That the certificate's round number is consistent with the current chain state.

Until the real implementation is available, the node should not accept inbound `PerasCert` messages from untrusted peers (i.e., the ObjectDiffusion inbound handler for certificates should be disabled or gated behind a feature flag that is off by default in production).

---

### Proof of Concept

1. Connect to a target node as a peer via the node-to-node protocol.
2. Observe (via ChainSync) a block hash `H` currently in the node's VolatileDB on a minority fork.
3. Construct a `PerasCert { pcCertRound = R, pcCertBoostedBlock = pointFromHash H }` for any round `R` not yet in the node's `PerasCertDB`.
4. Send the certificate via the Peras certificate ObjectDiffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. `ChainDB.addPerasCertAsync` enqueues the certificate; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for block `H`.
7. `preferAnchoredCandidate` now computes `wsvTotalWeight` for the fork containing `H` as `blockNo(H) + perasWeight`, which may exceed the current chain's weight.
8. The node switches to the minority fork containing `H`. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L495-531)
```haskell
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
