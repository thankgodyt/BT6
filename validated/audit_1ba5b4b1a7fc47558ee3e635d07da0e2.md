### Title
Peras Certificate Validation Stub Unconditionally Accepts All Certificates, Enabling Unprivileged Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` (success) for every certificate, performing no cryptographic or semantic checks. Because this function is the sole validation gate used by the production Peras certificate inbound pipeline (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject an arbitrary crafted `PerasCert` that boosts any block in the VolatileDB. The injected weight is then consumed by chain selection, potentially causing the node to prefer a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` instance defined for all block types is explicitly marked as a degenerate placeholder:

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

This stub is directly wired into the production certificate inbound path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` is designed to disconnect peers that send invalid certificates — but since `validatePerasCert` always returns `Right`, no peer is ever rejected: [3](#0-2) 

Every accepted certificate is forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` then stores the certificate in the `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

The `PerasWeightSnapshot` derived from the `PerasCertDB` is consumed directly by `chainSelection` and `constructPreferableCandidates` to compare candidate chains: [5](#0-4) 

The `PerasCertDB` implementation itself also carries a matching TODO acknowledging that non-trivial validation is absent: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash in the node's VolatileDB as the boosted block. Because `validatePerasCert` performs no BLS aggregate-signature verification, no committee-membership check, and no round-number plausibility check, the certificate passes validation unconditionally. The injected weight is added to the `PerasWeightSnapshot` and used in `preferAnchoredCandidate` / `compareChainDiffs`, causing the node to prefer the adversarially boosted fork over the canonical chain. This is a chain-selection safety failure: an honest node can be made to adopt a non-canonical chain by a single unprivileged peer sending a single crafted message.

---

### Likelihood Explanation

The Peras certificate mini-protocol is wired into the production diffusion layer (`makePerasCertPoolWriterFromChainDB`). Any connected peer can send `PerasCert` objects. No stake, key material, or operator access is required. The attack requires only knowledge of a block hash present in the target node's VolatileDB (obtainable via ChainSync). There are no low-probability prerequisites.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic and semantic validation before the Peras certificate pipeline is active in production. At minimum, the validation must verify:
1. The BLS aggregate signature over `(roundNo, boostedBlock)`.
2. That each signer's seat index corresponds to a legitimate committee member for the given round.
3. That the aggregate stake of signers meets the quorum threshold.

Until real validation is in place, the inbound certificate pipeline should be disabled or gated behind a feature flag that is off by default, preventing untrusted peers from injecting weight into chain selection.

---

### Proof of Concept

1. Connect to a target node that has block `B` in its VolatileDB (learn its hash via ChainSync).
2. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = B }` for any round `r`.
3. Send the certificate via the Peras certificate mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
5. `ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` stores it in `PerasCertDB` and calls `chainSelectionForBlock` for `B`.
6. `getPerasWeightSnapshot` now returns a snapshot with extra weight on `B`; `preferAnchoredCandidate` and `compareChainDiffs` use this weight to prefer any chain containing `B` over the current selection.
7. The node switches to the adversarially boosted fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
```
