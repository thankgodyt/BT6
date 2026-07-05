### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Weight Boost — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, regardless of cryptographic content or stake backing. Because this function is wired directly into the peer-facing certificate ingestion pipeline (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can submit a crafted `PerasCert` for an arbitrary block, have it accepted as "validated," and cause the local node to apply a full Peras weight boost to that block during chain selection — potentially switching to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must verify a certificate's cryptographic proof and stake quorum before the certificate is trusted. The sole production instance — the degenerate `StandardHash blk` instance — skips all verification:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- full boost, unconditionally
      }
``` [1](#0-0) 

This stub is the **only** instance in the codebase, explicitly labelled as a placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

The stub is wired into the production peer-facing certificate ingestion path in `makePerasCertPoolWriterFromChainDB`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on each inbound certificate; if all return `Right`, every certificate is timestamped and forwarded to `addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and triggers chain selection for the boosted block: [5](#0-4) 

The `PerasCertDB` implementation also carries a matching TODO confirming no secondary validation occurs there either:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ...
``` [6](#0-5) 

The accepted certificate's boost is then materialised into the `PerasWeightSnapshot` used by `preferAnchoredCandidate` / `wsvTotalWeight` during chain selection: [7](#0-6) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer can craft a `PerasCert` naming any block hash and any round number. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and its full `perasWeight` boost is applied to the named block in the `PerasWeightSnapshot`. Chain selection then computes `wsvTotalWeight = BlockNo + PerasWeight` for every candidate fragment. A boosted fork can exceed the honest chain's total weight, causing the node to roll back to and adopt the adversary's chain — a direct chain-selection safety failure triggered by a single crafted network message.

---

### Likelihood Explanation

**Likelihood: High.** The attack requires only that the adversary be a connected peer and know the hash of a block in the VolatileDB (trivially obtained via ChainSync). No key material, stake, or privileged access is needed. The vulnerable code path is the default production path for all block types.

---

### Recommendation

1. Implement a real `validatePerasCert` for each concrete block type that verifies the aggregate BLS/committee signature and confirms the vote-stake quorum threshold is met before constructing a `ValidatedPerasCert`.
2. Until a real implementation exists, gate the entire Peras certificate ingestion pipeline behind a feature flag so it is unreachable on production nodes.
3. Add a property-based test asserting that `validatePerasCert` rejects certificates with invalid or missing cryptographic proofs.

---

### Proof of Concept

**Setup:** Node A is an honest node connected to adversarial peer B. The VolatileDB contains block `X` on a minority fork.

1. Peer B constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(X) }` — no signature, no VRF proof, no stake evidence required.
2. B sends the certificate via the Peras certificate mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
4. `addPerasCertAsync` enqueues the cert; `chainSelSync` adds it to `PerasCertDB`.
5. `implGetWeightSnapshot` builds a `PerasWeightSnapshot` that maps `pointOf(X)` → `perasWeight`.
6. `weightedSelectView` computes `wsvTotalWeight` for the fork containing `X` as `BlockNo(X) + perasWeight`, which now exceeds the honest chain's `BlockNo`.
7. `preferAnchoredCandidate` returns `ShouldSwitch`; node A rolls back to and adopts the adversary's fork.

The analog to the external report is exact: just as `_normalizeUnderlyingTokensToDebt` credits debt reduction at a fixed 1:1 ratio regardless of actual token value, `validatePerasCert` credits a full chain-weight boost at a fixed `perasWeight` regardless of actual cryptographic validity — and an unprivileged actor exploits the gap to steer the system toward their preferred state.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
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
```
