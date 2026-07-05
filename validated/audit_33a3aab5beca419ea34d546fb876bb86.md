### Title
Peras Certificate Validation Bypass: `validatePerasCert` Stub Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` type-class instance used for all block types implements `validatePerasCert` as an unconditional stub that always returns `Right` (success), performing zero cryptographic or semantic checks. The batch certificate ingestion path `processCerts` calls this stub for every inbound certificate received from a peer. As a result, any connected peer can inject arbitrary Peras certificates into the node's `PerasCertDB`, which then influence chain selection by artificially boosting arbitrary blocks.

---

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory validation gate for inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The sole concrete instance — a degenerate catch-all for all block types — implements this as an unconditional stub:

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

No quorum check, no aggregate BLS signature verification, no round-number validity check, no boosted-block existence check — every certificate is unconditionally promoted to `ValidatedPerasCert`.

This stub is called directly by `processCerts`, the batch inbound-certificate handler wired to the ObjectDiffusion mini-protocol:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

The only guard is a duplicate-round-number filter (`alreadyInDb`). Because `validateCert` = `validatePerasCert mkPerasParams` always returns `Right`, the `(errs, _)` branch is unreachable and every novel certificate is accepted.

The production writer wired to the ChainDB passes this stub:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    (validatePerasCert mkPerasParams)   -- always Right
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [3](#0-2) 

Once accepted, the certificate is enqueued via `addPerasCertAsync` and processed by `chainSelSync`, which adds it to `cdbPerasCertDB` and triggers `chainSelectionForBlock` for the boosted block:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `PerasWeightSnapshot` derived from these certificates is then used in `compareCandidateChains` to prefer chains with higher Peras boost weight, directly affecting which chain the node selects as its tip.

---

### Impact Explanation

**Impact: High — Chain selection manipulation by an unprivileged peer.**

An adversary connected via the ObjectDiffusion mini-protocol can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on a weaker fork. Because `validatePerasCert` never rejects anything, the certificate is stored and its `perasWeight` (currently 15 slots worth of boost) is added to the `PerasWeightSnapshot` for that block. Chain selection then compares candidates using this inflated weight, potentially causing the honest node to prefer and switch to the adversary's fork over the canonical chain. This violates the Peras protocol's security assumption that only certificates backed by a genuine quorum of stake-weighted votes should influence chain selection.

---

### Likelihood Explanation

**Likelihood: High.**

The ObjectDiffusion mini-protocol for Peras certificates is fully wired in production code (`makePerasCertPoolWriterFromChainDB`). Any peer that establishes a connection and speaks the ObjectDiffusion protocol can send a batch of certificates. The only barrier is the duplicate-round-number filter, which an attacker trivially avoids by using fresh round numbers. No stake, no keys, and no special privileges are required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion path is enabled in production. At minimum, the implementation must:

1. Verify the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set.
2. Verify each voter's eligibility proof (VRF output for non-persistent members, committee membership for persistent members).
3. Confirm the total stake of the voter set meets the quorum threshold (`stakeAboveThreshold`).
4. Confirm the certificate's round number is within the valid window relative to the current tip.

Until real validation is in place, the ObjectDiffusion inbound path for Peras certificates should be disabled or gated behind a feature flag so that no peer-supplied certificate can reach `chainSelectionForBlock`.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node with the Peras ObjectDiffusion mini-protocol enabled.
2. Connect an adversarial peer that speaks the ObjectDiffusion protocol.
3. The adversary sends a batch containing one `PerasCert { pcCertRound = R, pcCertBoostedBlock = <tip of weaker fork> }` where `R` is a round number not yet in the node's `PerasCertDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = 15 })`.
5. The certificate is enqueued via `addPerasCertAsync` and processed by `chainSelSync`.
6. `chainSelectionForBlock` is triggered for the boosted block; the `PerasWeightSnapshot` now shows a boost of 15 for the weaker fork's tip.
7. `compareCandidateChains` uses this snapshot; if the weaker fork's boosted weight exceeds the canonical chain's weight, the node switches to the adversary's fork.

The root cause — `validatePerasCert` always returning `Right` — is confirmed at: [1](#0-0) 

The batch ingestion path that calls it without any fallback check is at: [5](#0-4)

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
