### Title
Peras Certificate Validation Unconditionally Accepts All Certificates, Enabling Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the production `BlockSupportsPeras` instance unconditionally returns `Right` for every certificate it receives, performing no actual cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` that passes this stub validation, gets stored in the `PerasCertDB`, and triggers chain selection for an arbitrary block — potentially causing an honest node to switch to an adversarial fork by artificially inflating its Peras weight.

---

### Finding Description

The `BlockSupportsPeras` instance (used for all `StandardHash blk`) implements `validatePerasCert` as a stub that always returns `Right`:

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

This stub is wired directly into the production certificate ingest path. `makePerasCertPoolWriterFromChainDB` — the writer used when receiving certificates from network peers — calls `validatePerasCert mkPerasParams` as its validation function:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert <$> certsNotAlreadyInDb`. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is unconditionally forwarded to `addCert`: [3](#0-2) 

Once added to the `PerasCertDB`, the certificate is processed by `chainSelSync` (`ChainSelAddPerasCert` branch), which adds the certificate's weight boost to the `PerasWeightSnapshot` and then calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then uses `preferAnchoredCandidate` with the updated `PerasWeightSnapshot`, comparing `wsvTotalWeight` (block number + weight boost) between the current chain and candidates: [5](#0-4) 

A crafted certificate pointing to a block on an adversarial fork inflates that fork's `wsvTotalWeight` by `perasWeight params`, potentially making it preferred over the honest chain.

---

### Impact Explanation

This is a **Critical bypass of Peras certificate validation**. An unprivileged peer can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on an adversarial fork.
2. Send it via the Peras certificate mini-protocol.
3. The certificate passes "validation" (always `Right`), is stored in the `PerasCertDB`, and its weight boost is applied to the target block.
4. Chain selection is triggered for the boosted block. If the adversarial fork's total weight (block count + boost) now exceeds the honest chain's weight, the node switches to the adversarial fork.

This enables unauthorized certificate acceptance and chain weight manipulation, directly matching the allowed impact: *"Bypass of... certificate/signature validation... that enables unauthorized... certificate acceptance"* and *"Chain selection... bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

The production certificate ingest path (`makePerasCertPoolWriterFromChainDB`) is active whenever Peras is enabled. Any peer connected via the Peras certificate mini-protocol can send a crafted certificate. No stake, keys, or operator compromise is required. The stub is explicitly marked with a `TODO` referencing a known open issue, confirming it is not a dead code path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic validation before the production certificate ingest path is used. Specifically:

1. Verify the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)`.
2. Verify committee membership and eligibility proofs for all voters in `pcVoters`.
3. Verify that the quorum threshold is met by the included voters' stake.
4. Only return `Right` if all checks pass.

Until real validation is implemented, the production `makePerasCertPoolWriterFromChainDB` path should not be reachable from untrusted peers.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → Peras cert mini-protocol
  → makePerasCertPoolWriterFromChainDB.opwAddObjects [craftedCert]
  → processCerts ... (validatePerasCert mkPerasParams) ...
  → validatePerasCert always returns Right ValidatedPerasCert{vpcCertBoost = perasWeight params}
  → addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
  → chainSelSync (ChainSelAddPerasCert cert ...)
  → PerasCertDB.addCert  -- cert stored, weight snapshot updated
  → chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
  → preferAnchoredCandidate: adversarial fork now has wsvTotalWeight = blockNo + perasWeight
  → node switches to adversarial fork
```

**Concrete scenario:** Suppose the honest chain has tip at block 1000 and the adversarial fork diverges at block 990 with tip at block 999 (one block shorter). With `perasWeight = 15` (a plausible mainnet value per the benchmark), a single crafted certificate boosting block 999 gives the adversarial fork `wsvTotalWeight = 999 + 15 = 1014 > 1000`, causing the honest node to switch to the adversarial fork — a consensus safety failure. [1](#0-0) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
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
