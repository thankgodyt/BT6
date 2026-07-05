### Title
`validatePerasCert` Unconditionally Returns Success, Allowing Crafted Certificates to Manipulate Peras Chain Selection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that always returns `Right` (success) without performing any cryptographic or semantic checks. When Peras is enabled, any unprivileged peer can send crafted certificates with arbitrary round numbers and boosted-block pointers. These certificates pass validation unconditionally, are stored in the `PerasCertDB`, and their weight boost is applied during chain selection — enabling an attacker to make an honest node prefer a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` never rejects a certificate:** [1](#0-0) 

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

This is the **only** instance of `BlockSupportsPeras` in the codebase (a universal instance over all `StandardHash blk`). No production override exists. The function never inspects the certificate's BLS aggregate signature, committee membership, round-number bounds, or boosted-block validity — it unconditionally wraps the raw certificate in `ValidatedPerasCert` and returns `Right`.

**Attacker-controlled entry path — `processCerts` in the Peras certificate diffusion pool:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` wires the production certificate ingestion path. It calls `processCerts` with `validatePerasCert mkPerasParams` as the validator: [3](#0-2) 

`processCerts` partitions certificates into valid/invalid using the supplied validator. Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never taken; every certificate — including crafted ones — reaches `addCert`.

**Propagation into chain selection:**

Once stored in the `PerasCertDB`, the certificate's boost is included in the `PerasWeightSnapshot` returned by `implGetWeightSnapshot`: [4](#0-3) 

`chainSelSync` reads this snapshot and passes it to `chainSelectionForBlock`, which uses `preferAnchoredCandidate` to compare candidate chains by Peras-weighted length: [5](#0-4) 

A crafted certificate boosting a block on a fork can make that fork's weighted length exceed the canonical chain's, triggering a chain switch.

**Analog to the external report:** The external bug omits `user_state.is_blacklisted = true` after a refund, leaving the restriction flag unset. Here, `validatePerasCert` omits the `Left (PerasValidationErr ...)` return path entirely — the "invalid" state is never set — so the downstream restriction (rejecting the certificate) is never enforced.

---

### Impact Explanation

**Impact: High** — Chain selection manipulation.

An unprivileged peer connected via the Peras certificate diffusion mini-protocol can inject certificates with arbitrary `pcCertRound` and `pcCertBoostedBlock` values. Because no signature or committee check is performed, the honest node accepts these certificates, stores them, and applies their weight boost during chain selection. With a sufficient boost, the node can be made to prefer and adopt a non-canonical fork, violating chain-selection safety beyond the intended Peras security assumptions.

---

### Likelihood Explanation

**Likelihood: Medium.**

Peras is not enabled by default (`eraPerasRoundLength` must be set), but the code is production-ready infrastructure and the diffusion mini-protocol is fully wired. Any peer reachable over the network can send Peras certificate objects once the protocol is active. No stake, key material, or privileged access is required — only a network connection and the ability to construct a syntactically valid `PerasCert` record.

---

### Recommendation

Replace the stub with real validation before the `ValidatedPerasCert` wrapper is applied:

```diff
validatePerasCert params cert =
-   Right
-     ValidatedPerasCert
-       { vpcCert = cert
-       , vpcCertBoost = perasWeight params
-       }
+   do
+     verifyBLSAggregateSignature params cert
+       `orLeft` PerasValidationErrBadSignature
+     verifyCommitteeMembership params cert
+       `orLeft` PerasValidationErrBadCommittee
+     verifyRoundBounds params cert
+       `orLeft` PerasValidationErrBadRound
+     pure ValidatedPerasCert
+       { vpcCert = cert
+       , vpcCertBoost = perasWeight params
+       }
```

The tracked issue (`cardano-peras/issues/120`) should be resolved before Peras is enabled on any network where adversarial peers are possible.

---

### Proof of Concept

1. Enable Peras on a private testnet by setting a non-zero `eraPerasRoundLength`.
2. Connect a malicious peer to an honest node via the Peras certificate diffusion mini-protocol.
3. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a shorter fork already present in the honest node's VolatileDB.
4. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams`, which returns `Right` unconditionally.
5. The certificate is stored in the `PerasCertDB`; `implGetWeightSnapshot` now includes the boost for the fork block.
6. On the next chain selection event (e.g., a new block arrives), `preferAnchoredCandidate` computes the fork's weighted length as exceeding the canonical chain's.
7. The honest node switches to the non-canonical fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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
