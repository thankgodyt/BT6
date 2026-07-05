### Title
Peras Certificate Validation Universally Bypassed via Stub `validatePerasCert` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or semantic validation. Because this stub is the only instance in the production codebase, any peer can inject an arbitrary certificate that boosts any block, directly manipulating chain selection.

---

### Finding Description

In `SupportsPeras.hs`, a catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` provides the only production implementation of `validatePerasCert`. The implementation unconditionally returns `Right` without checking the BLS aggregate signature, vote quorum, round number validity, or voter eligibility:

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

This stub is called directly in the production inbound-certificate pipeline. In `PerasCert.hs`, the `ObjectPoolWriter` for Peras certificates invokes `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

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

`processCerts` partitions the results of `validateCert <$> certsNotAlreadyInDb`. Because `validatePerasCert` always returns `Right`, the left partition (errors) is always empty and every certificate is forwarded to `addCert`: [3](#0-2) 

Each accepted certificate is then passed to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes it by adding the certificate to the `PerasCertDB` and triggering `chainSelectionForBlock` for the boosted block: [4](#0-3) 

During chain selection, `preferAnchoredCandidate` uses `weightedSelectView`, which sums `weightBoostOfFragment` over the candidate. The accepted certificate contributes `perasWeight params` to the boosted block's point, making any chain containing that block appear heavier: [5](#0-4) 

**Analog to the external report:** Just as `nonRSRTrade` sets `req.minBuyAmount = 0` — a stub value that causes a downstream security gate (`EasyAuction.initiateAuction` requiring `_minBuyAmount > 0`) to be trivially circumvented — `validatePerasCert` is a stub that bypasses all downstream cryptographic checks, allowing the critical Peras certificate security gate to be trivially circumvented. In both cases, a placeholder value in one function causes a critical validation step to be skipped, with direct protocol-level consequences.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` for any block point and any round number, send it via the Peras certificate diffusion protocol, and have it unconditionally accepted. The accepted certificate adds `perasWeight params` additional weight to the target block's chain. By targeting a block on an adversarial fork, the attacker can make that fork appear heavier than the honest chain, causing honest nodes to switch to the adversarial chain. This is a **Critical** bypass of Peras certificate verification that enables unauthorized certificate acceptance and chain-selection manipulation — matching the allowed impact scope: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

The attack requires only a network connection to a target node and the ability to send a well-formed (but cryptographically invalid) `PerasCert` message via the Peras object-diffusion miniprotocol. No stake, keys, or privileged access are needed. The code path is unconditionally reachable from any peer, and the stub is the only `BlockSupportsPeras` instance in the production codebase.

---

### Recommendation

Implement actual cryptographic and semantic validation in `validatePerasCert` before enabling Peras certificate diffusion in production. At minimum:
1. Verify the BLS aggregate signature over the certificate message.
2. Check that the round number is within the valid range.
3. Verify that the voters are eligible and that quorum is reached.
4. Ensure the boosted block exists and is on a valid chain.

Until real validation is implemented, the Peras certificate diffusion protocol should be disabled or gated behind a feature flag that is off by default in production nodes.

---

### Proof of Concept

1. Attacker connects to a node as a peer via the Peras certificate diffusion miniprotocol.
2. Attacker crafts `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint }` for any round `r` and any block point on an adversarial fork.
3. The node's `opwAddObjects` handler calls `processCerts … (validatePerasCert mkPerasParams) … [cert]`.
4. `validatePerasCert mkPerasParams cert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` with no validation performed. [6](#0-5) 
5. The certificate is added to the `PerasCertDB`.
6. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block, giving it `perasWeight params` additional weight. [7](#0-6) 
7. `preferAnchoredCandidate` now prefers any chain containing the adversarial block, causing the honest node to switch to the adversarial chain. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
