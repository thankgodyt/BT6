### Title
Unconditional `validatePerasCert` Stub Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance — the only production instance — implements `validatePerasCert` as an unconditional stub that always returns `Right`, accepting every certificate without any cryptographic or structural check. Because the Peras object-diffusion inbound path calls this function on every peer-supplied certificate before storing it and triggering chain selection, an unprivileged peer can inject an arbitrary crafted `PerasCert` that boosts any block, causing the receiving node to re-run chain selection with an artificial weight advantage for that block and potentially switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` always succeeds:**

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

This is the **only** `BlockSupportsPeras` instance in the codebase. It is explicitly marked as a degenerate placeholder ("TODO: degenerate instance for all blks to get things to compile"), but it is the instance that runs in production for all block types. [2](#0-1) 

**Inbound certificate processing path:**

`makePerasCertPoolWriterFromChainDB` wires this stub directly into the network-facing object-diffusion writer:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- ← always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` partitions results from `validateCert`: if all certs pass (which they always do), each is forwarded to `addCert`. No other validation gate exists. [4](#0-3) 

**Chain-selection side-effect:**

`addPerasCertAsync` enqueues the accepted certificate into the `ChainSelQueue`. The `chainSelSync` handler for `ChainSelAddPerasCert` then calls `chainSelectionForBlock` for the boosted block, applying the Peras weight boost from the certificate to chain selection: [5](#0-4) 

The weight boost (`vpcCertBoost = perasWeight params`) is assigned unconditionally by the stub and is used by `getPerasWeightSnapshot` during chain comparison. [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as `pcCertBoostedBlock`. The certificate passes `validatePerasCert` unconditionally, is stored in `PerasCertDB`, and triggers `chainSelectionForBlock` for the named block. If that block exists in the node's VolatileDB, chain selection re-runs with an artificial weight boost, potentially causing the node to switch to a non-canonical fork. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or adversarially chosen chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

The Peras object-diffusion protocol is wired into the production `NodeKernel` and `ChainDB`. Any connected peer that speaks the Peras object-diffusion mini-protocol can send a batch of `PerasCert` objects. No stake, key material, or privileged access is required. The only prerequisite is that the boosted block is present in the target node's VolatileDB, which is trivially achievable by first diffusing the block normally.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature over `(electionId, candidate)` against the aggregate verification key of the declared voters.
2. That the declared voters are eligible committee members for the claimed round (VRF eligibility proofs for non-persistent members).
3. That the total stake of the declared voters meets the quorum threshold.

Until the real implementation is ready, the inbound certificate path (`makePerasCertPoolWriterFromChainDB` / `processCerts`) should reject all externally received certificates rather than accepting them unconditionally, or the object-diffusion server for Peras certificates should not be started.

---

### Proof of Concept

1. Attacker connects to a victim node and diffuses a valid block `B` (any block the attacker wants boosted) so it lands in the victim's VolatileDB.
2. Attacker sends a `PerasCert` message via the Peras object-diffusion mini-protocol with `pcCertBoostedBlock = point(B)` and any `pcCertRound`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
4. The cert is forwarded to `ChainDB.addPerasCertAsync`.
5. `chainSelSync` fires `chainSelectionForBlock` for block `B` with the artificial weight boost.
6. If the chain containing `B` is now heavier than the current selection (due to the boost), the node switches to it.
7. The attacker can repeat with different `pcCertRound` values (one cert per round is stored) to accumulate boosts across multiple rounds, further amplifying the weight advantage. [1](#0-0) [3](#0-2) [4](#0-3) [5](#0-4)

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
