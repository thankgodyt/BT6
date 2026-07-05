### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance unconditionally returns `Right` for every inbound certificate, performing no cryptographic or semantic checks. This stub is wired directly into the production inbound-certificate processing path (`processCerts` → `makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject arbitrary `PerasCert` objects that are accepted without verification and trigger chain selection for an attacker-chosen block, potentially causing an honest node to switch to an adversarial fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must reject invalid Peras certificates before they enter the node's state. [1](#0-0) 

The only concrete instance in the codebase is the universal stub:

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
``` [2](#0-1) 

This stub is explicitly self-described as a "degenerate instance for all blks to get things to compile": [3](#0-2) 

The production inbound-certificate handler `processCerts` calls this stub as its sole validation step:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces an empty error list, so every certificate from every peer is unconditionally accepted. The production writer `makePerasCertPoolWriterFromChainDB` passes this stub directly: [5](#0-4) 

Once accepted, the certificate is forwarded to `addPerasCertAsync` → `chainSelSync`, which triggers `chainSelectionForBlock` for the attacker-supplied `pcCertBoostedBlock`: [6](#0-5) 

The injected certificate carries the full configured `perasWeight` boost, which is applied to the attacker-chosen block during chain comparison.

---

### Impact Explanation

An adversary who controls a peer node can send a `PerasCert` whose `pcCertBoostedBlock` points to a block on an adversarial fork. The certificate passes the stub validation, is stored in the `PerasCertDB`, and triggers chain selection. The adversarial fork gains the full Peras weight boost. If that boost causes the adversarial fork's weight to exceed the honest chain's weight, the honest node switches to the adversarial fork — a chain-selection safety failure. No cryptographic material (BLS aggregate signature, VRF output, committee membership proof) is ever checked.

This matches the allowed impact class: **Bypass of Peras certificate checks that enables unauthorized certificate acceptance**, with downstream chain-selection divergence.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a standard network-facing protocol. Any peer that connects to the node can send a batch of `PerasCert` objects. The only pre-filter is deduplication by round number (`Set.member roundNo alreadyInDb`); a fresh round number bypasses even that. No stake, key, or operator privilege is required. The attack is therefore reachable by any unprivileged peer on the network.

---

### Recommendation

Implement real cryptographic and semantic validation inside `validatePerasCert` before the Peras certificate diffusion path is enabled in production. At minimum this must include:

1. Verifying the aggregate BLS signature against the committee's aggregate verification key (as already implemented for the WFALS committee in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs`).
2. Checking that the certificate's round number is within the acceptable window relative to the current chain tip.
3. Verifying committee membership and that the signers collectively hold sufficient stake to meet the quorum threshold.
4. Confirming that `pcCertBoostedBlock` refers to a known, non-genesis block point.

Until real validation is in place, the ObjectDiffusion inbound path for Peras certificates should not be exposed to untrusted peers.

---

### Proof of Concept

1. Attacker connects to a target node via the ObjectDiffusion mini-protocol for Peras certificates.
2. Attacker constructs `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = adversarialForkTip }` where `freshRound` is not yet in the node's `PerasCertDB` and `adversarialForkTip` is the tip of an adversarial fork the attacker has been building.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`. Because the implementation is `Right ValidatedPerasCert{...}` unconditionally, the certificate passes.
4. The certificate is added to the `PerasCertDB` via `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event.
5. `chainSelSync` processes the event: the boosted block is not on the current chain, so `chainSelectionForBlock` is called for `adversarialForkTip`.
6. Chain selection now compares the honest chain against the adversarial fork with the injected `perasWeight` boost applied to `adversarialForkTip`. If the boost tips the balance, the node adopts the adversarial fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

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
