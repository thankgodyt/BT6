### Title
Peras Certificate Validation Bypass via Hardcoded Default Parameters and Stub `validatePerasCert` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` and `File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The production Peras certificate inbound-diffusion path calls `validatePerasCert mkPerasParams` — a hardcoded default parameter bundle — instead of the actual per-node Peras configuration. The `validatePerasCert` implementation itself is a degenerate stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or protocol-rule checks whatsoever. When Peras is enabled, any unprivileged peer can send an arbitrarily crafted `PerasCert` that will be accepted, stored in the `PerasCertDB`, and used to boost a block's chain-selection weight, potentially causing the node to switch to an adversarially chosen chain.

---

### Finding Description

**Root cause 1 — stub `validatePerasCert` always accepts:**

The `BlockSupportsPeras` instance in `SupportsPeras.hs` is explicitly labelled a "degenerate instance … to get things to compile" and its `validatePerasCert` body unconditionally returns `Right`:

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

No round-number range check, no cryptographic signature check, no committee-membership check, no quorum-stake check — every certificate is accepted. [1](#0-0) 

**Root cause 2 — hardcoded `mkPerasParams` in the production inbound path:**

Both production pool-writer constructors (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) pass the hardcoded default `mkPerasParams` to `validatePerasCert` instead of the actual node-configured `PerasParams`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

This is the direct analog to the external report: just as `maxExposureFactor` defaults to zero for existing markets and causes `getPSlippage()` to accept/reject incorrectly, here the Peras configuration parameters are never properly plumbed into the validation call site, so the validation function operates on wrong (hardcoded default) state and produces incorrect results — in this case, accepting every certificate unconditionally.

**`processCerts` — the reachable entry point:**

`processCerts` is the function that receives a batch of `PerasCert` objects from a remote peer, calls `validateCert` on each, and — if all pass — timestamps and stores them. Since `validateCert` is `validatePerasCert mkPerasParams` and that always returns `Right`, every peer-supplied certificate passes: [4](#0-3) 

After storage, `addPerasCertAsync` triggers chain selection for the boosted block: [5](#0-4) 

Chain selection then uses `weightedSelectView` / `preferAnchoredCandidate`, which adds `vpcCertBoost` (= `perasWeight mkPerasParams` = **15**) to the total weight of the boosted chain fragment: [6](#0-5) 

---

### Impact Explanation

**Impact: Critical** — Bypass of Peras certificate validation enables unauthorized certificate acceptance.

When Peras is enabled (`rnFeatureFlags` includes the Peras feature flag), an unprivileged peer can:

1. Craft a `PerasCert` naming any `pcCertRound` and any `pcCertBoostedBlock` (a block the attacker wants to boost).
2. Send it via the Peras certificate diffusion mini-protocol.
3. The receiving node's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` fires chain selection.
5. The boosted block's chain fragment gains +15 weight units, potentially making it heavier than the honest chain.
6. The node switches to the adversarially boosted chain.

This constitutes an unauthorized Peras certificate acceptance that directly corrupts chain selection — a consensus safety failure reachable from an unprivileged peer.

---

### Likelihood Explanation

**Likelihood: Medium.**

Peras is currently disabled by default (`eraPerasRoundLength = NoPerasEnabled`), so mainnet nodes are not immediately affected. However:

- The feature is explicitly designed for production deployment and is gated only by `rnFeatureFlags`.
- The production code path (`makePerasCertPoolWriterFromChainDB`) is already wired into the `ChainDB` and the diffusion layer.
- Any private testnet or early-adopter node that enables Peras is immediately vulnerable.
- The attack requires only the ability to connect as a peer and send a well-formed CBOR-encoded `PerasCert` — no keys, no stake, no special privileges.

---

### Recommendation

1. **Replace the stub `validatePerasCert`** with a real implementation that checks certificate round number, cryptographic signatures, committee membership, and quorum stake before returning `Right`. Track this against issue [#120](https://github.com/tweag/cardano-peras/issues/120).

2. **Plumb the actual `PerasParams` (or a `PerasCfg blk`)** through to `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` instead of using the hardcoded `mkPerasParams`. The TODO comments at lines 103 and 126 of `PerasCert.hs` already acknowledge this gap.

3. **Gate Peras certificate acceptance** behind a check that Peras is actually enabled for the current era before calling `processCerts`, so that nodes with Peras disabled cannot be tricked into storing adversarial certificates even if the validation stub is present.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  Peras cert diffusion mini-protocol
  │  PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlock }
  ▼
makePerasCertPoolWriterFromChainDB  [PerasCert.hs:118-133]
  │
  └─► processCerts ... (validatePerasCert mkPerasParams) ...  [PerasCert.hs:164-173]
          │
          │  validatePerasCert mkPerasParams cert
          │  = Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }
          │  -- always Right, no checks performed  [SupportsPeras.hs:353-358]
          ▼
      addCert . WithArrivalTime now $ validatedCert
          │
          ▼
      ChainDB.addPerasCertAsync chainDB cert  [PerasCert.hs:132]
          │
          ▼
      chainSelSync → chainSelectionForBlock adversarialBlock  [ChainSel.hs:531]
          │
          ▼
      weightedSelectView adds PerasWeight 15 to adversarialBlock's chain
      → node may switch to adversarially boosted chain
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
