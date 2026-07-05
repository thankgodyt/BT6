### Title
Stub `validatePerasCert` Unconditionally Accepts All Peer-Provided Peras Certificates Without Any Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic, structural, or quorum verification. This stub is wired directly into the production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject an arbitrary crafted `PerasCert` that will be accepted, stored in the `PerasCertDB`, and used to trigger chain selection for the boosted block, bypassing all Peras certificate authorization.

---

### Finding Description

**Root cause — stub validator always returns `Right`:**

The universal instance at `SupportsPeras.hs` lines 350–358 reads:

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

No signature check, no quorum proof, no round-number bounds, no voter eligibility — the function ignores every field of `cert` and wraps it unconditionally as `ValidatedPerasCert`. [1](#0-0) 

**Production call site — stub is passed directly to the inbound pipeline:**

`makePerasCertPoolWriterFromChainDB` (the production writer used by `NodeKernel`) passes this stub as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

**`processCerts` — accepts and stores every certificate that passes the stub:**

`processCerts` calls `validateCert` on each inbound certificate; if all return `Right`, they are timestamped and forwarded to `addCert` (which calls `ChainDB.addPerasCertAsync`): [3](#0-2) 

**Chain selection trigger — accepted certificate immediately influences chain selection:**

`ChainDB.addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. `chainSelSync` then looks up the boosted block in the `VolatileDB` and, if found, calls `chainSelectionForBlock` for it, giving the boosted block additional Peras weight: [4](#0-3) 

---

### Impact Explanation

**Impact: Critical — bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

Because `validatePerasCert` never rejects any certificate, an unprivileged peer can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the node's `VolatileDB`.
2. Send it via the ObjectDiffusion mini-protocol.
3. The node accepts it as `ValidatedPerasCert`, stores it in `PerasCertDB`, and triggers `chainSelectionForBlock` for the boosted block.
4. The boosted block now carries additional Peras weight (`vpcCertBoost = perasWeight params`), potentially making a competing (non-canonical) chain preferred over the honest chain.

This directly bypasses the Peras certificate authorization that is supposed to require a quorum of stake-weighted committee votes before a block can be boosted. A single peer with no stake can manufacture the effect of a quorum certificate. [5](#0-4) 

---

### Likelihood Explanation

**Likelihood: High.**

- The ObjectDiffusion mini-protocol is a standard node-to-node protocol; any peer that connects can send `PerasCert` objects.
- No privilege, stake, or key material is required — the attacker only needs a network connection to the target node.
- The stub is the **only** implementation of `validatePerasCert` in the codebase (the universal `instance StandardHash blk => BlockSupportsPeras blk` covers all block types including the production Cardano block).
- The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known placeholder, not an intentional design choice, meaning it is present in any deployment that includes Peras support. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that checks, at minimum:

1. **Aggregate BLS signature** over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set (using the concrete `V1.PerasCert` structure which already carries `pcSignature :: AggregateVoteSignature PerasBLSCrypto`).
2. **Quorum threshold**: total stake of the voters in `pcVoters` must exceed the configured quorum for the given `PerasCfg`.
3. **Voter eligibility**: each voter's eligibility proof (`PersistentPerasVoteEligibilityProof` or `NonPersistentPerasVoteEligibilityProof`) must be verified against the committee selection data for `pcCertRound`.
4. **Round bounds**: `pcCertRound` must be within the valid window relative to the current chain tip.

Until the real implementation is in place, the stub should be replaced with `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that no peer-provided certificate can influence chain selection. [7](#0-6) 

---

### Proof of Concept

**Setup:** A private testnet with at least two nodes, both running a build that includes the Peras ObjectDiffusion mini-protocol.

**Steps:**

1. Connect an attacker-controlled peer to the target node via the standard node-to-node mini-protocol handshake.
2. Identify a block `B` in the target node's `VolatileDB` that is on a competing (non-preferred) fork. Its `Point` (slot + hash) is obtainable via the `ChainSync` protocol.
3. Craft a `PerasCert` with:
   - `pcCertRound` = any valid `PerasRoundNo`
   - `pcCertBoostedBlock` = `Point` of block `B`
   - Any bytes for `pcSignature` and `pcVoters` (they are never checked)
4. Send the crafted certificate via the ObjectDiffusion protocol's `MsgObjects` message.
5. **Expected result:** `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`. The certificate is stored in `PerasCertDB`. `chainSelSync` is triggered for block `B`, which now carries Peras weight. If the weight boost is sufficient, the node switches its preferred chain to the fork containing `B`, diverging from the honest chain. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
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
