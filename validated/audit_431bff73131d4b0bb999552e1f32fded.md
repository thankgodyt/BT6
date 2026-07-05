### Title
`validatePerasCert` Performs No Authorization Check, Allowing Any Peer to Inject Arbitrary Peras Certificates That Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or committee-quorum authorization checks. Any unprivileged peer connected via the Peras certificate object-diffusion mini-protocol can inject a crafted `PerasCert` naming any block as the boosted block. The certificate is accepted, stored in the `PerasCertDB`, and immediately fed into chain selection with a full `perasWeight` boost, causing the node to prefer a non-canonical fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

In the sole production instance of `BlockSupportsPeras` (the degenerate catch-all instance for all `blk`), `validatePerasCert` is:

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

No check is performed on:
- A cryptographic aggregate signature proving a quorum of committee members voted for `pcCertBoostedBlock`
- Committee membership or eligibility of the claimed voters
- Whether `pcCertRound` is consistent with the boosted block's slot
- Any binding between the certificate's claimed round and the actual ledger state

This is the only `BlockSupportsPeras` instance in the codebase (declared as `instance StandardHash blk => BlockSupportsPeras blk`), so it is the code path executed for all blocks. [2](#0-1) 

**Attacker-controlled entry path — `processCerts` via object diffusion:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as the sole validator for inbound peer-supplied certificates:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on each cert and, because `validatePerasCert` always returns `Right`, every cert passes and is forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain selection impact — `chainSelSync` boosts the attacker-chosen block:**

`addPerasCertAsync` enqueues the certificate into the `ChainSelQueue`. The background `chainSelSync` handler then:
1. Adds the cert to `PerasCertDB`
2. Looks up the boosted block in `VolatileDB`
3. Calls `chainSelectionForBlock` for that block, now carrying the full `perasWeight` boost [5](#0-4) 

The `PerasWeightSnapshot` used during chain selection reflects the injected boost, causing the node to prefer the fork containing the attacker-chosen block over the honest canonical chain. [6](#0-5) 

---

### Impact Explanation

**Severity: High — Chain selection error.**

An unprivileged peer can make an honest node permanently prefer a non-canonical chain. By injecting a certificate that boosts a block on a minority fork, the attacker inflates that fork's Peras weight beyond the honest chain's weight. The node switches to the fork, diverging from the rest of the network. This breaks the chain-selection invariant that the node should follow the heaviest honest chain, and constitutes a consensus safety failure reachable without any key compromise or stake majority.

The `perasWeight` boost is applied unconditionally to the attacker-chosen block: [7](#0-6) 

---

### Likelihood Explanation

**High.** Any peer connected via the Peras certificate object-diffusion mini-protocol can send a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock`. No special privilege, key material, or stake is required. The attacker only needs to know the hash of a block in the target node's `VolatileDB` (obtainable via the ChainSync mini-protocol). The attack is deterministic and requires a single malformed message.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(electionId, candidate)` using the aggregated public keys of the claimed committee members.
2. Checks that the claimed voters form a valid quorum (total stake ≥ quorum threshold) according to the stake distribution for the relevant epoch.
3. Verifies that `pcCertRound` is consistent with the slot of `pcCertBoostedBlock` under the Peras round-length parameters.
4. Verifies committee membership and eligibility (VRF proofs for non-persistent members) for each claimed voter.

Until the real implementation is available, the stub should at minimum reject all inbound peer-supplied certificates (return `Left PerasValidationErr`) rather than accept them unconditionally, so that the Peras diffusion path is safely disabled.

---

### Proof of Concept

A private testnet with Peras enabled and two nodes (honest node H, attacker node A):

1. A observes via ChainSync that H's VolatileDB contains block `B_fork` on a minority fork at slot `s`.
2. A constructs `PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B_fork }` for any round `r`.
3. A sends this certificate to H over the Peras cert object-diffusion mini-protocol.
4. H's `processCerts` calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` without any check.
5. H's `chainSelSync` adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for `B_fork`.
6. The `PerasWeightSnapshot` now shows `B_fork` carrying `perasWeight` extra weight.
7. If `perasWeight` exceeds the honest chain's length advantage, H switches to the fork containing `B_fork`, diverging from the network. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
