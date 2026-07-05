### Title
Peras Certificate Validation Unconditionally Accepts All Peer-Supplied Certificates, Enabling Unauthorized Chain Selection Boost — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate, regardless of content. Any unprivileged peer can submit a crafted `PerasCert` via the object-diffusion mini-protocol; the certificate passes "validation," is stored in the `PerasCertDB`, and immediately triggers `chainSelectionForBlock` with `noPunishment` for the attacker-chosen boosted block. Because the Peras weight boost is applied to chain selection, the node can be made to prefer a non-canonical fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

`validatePerasCert` wraps every inbound certificate in `ValidatedPerasCert` unconditionally. The `Validated` wrapper is the type-level proof that validation succeeded; here it is issued without any check.

**Inbound path — reachable by any unprivileged peer:**

`makePerasVotePoolWriterFromChainDB` / `ObjectPool/PerasCert.hs` wires the object-diffusion writer directly to `processCerts … (validatePerasCert mkPerasParams) … (void . ChainDB.addPerasCertAsync chainDB)`. `processCerts` calls `validateCert` on each inbound cert; because the stub always returns `Right`, every cert passes and is forwarded to `addPerasCertAsync`.

**Chain-selection consequence — `chainSelectionForBlock` with `noPunishment`:**

`chainSelSync` for `ChainSelAddPerasCert` adds the cert to `PerasCertDB`, then calls:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

`chainSelectionForBlock` constructs candidate fragments and runs full chain selection, but the Peras weight snapshot now includes the attacker-supplied boost (`vpcCertBoost = perasWeight params`). If the boosted block is on a competing fork, the artificial weight can make that fork preferred over the honest chain.

**End-to-end exploit path:**

1. Attacker connects as a normal peer and sends a crafted `PerasCert` with `pcCertBoostedBlock` pointing to a block on a non-canonical fork already in the victim's VolatileDB.
2. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
3. The cert is stored in `PerasCertDB` and enqueued via `addPerasCertAsync`.
4. `chainSelSync` calls `chainSelectionForBlock` for the boosted block with `noPunishment`.
5. Chain selection evaluates the fork with the artificial Peras weight boost; if the boost exceeds the canonical chain's weight advantage, the node switches to the non-canonical fork.

---

### Impact Explanation

This is a **bypass of Peras certificate validation** that enables unauthorized certificate acceptance. An unprivileged peer can make an honest node prefer a non-canonical chain by injecting a fake certificate boost. This matches the allowed impact category:

> **Critical. Bypass of … certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks … that enables unauthorized … certificate acceptance.**

and

> **High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

The object-diffusion mini-protocol is reachable by any peer without special privileges, keys, or stake. The attacker only needs to craft a `PerasCert` whose `pcCertBoostedBlock` points to a block already present in the victim's VolatileDB. No cryptographic material is required because `validatePerasCert` performs no signature or committee-membership check. The attack is deterministic and reproducible on any node with Peras enabled (including private testnets).

---

### Recommendation

Implement genuine cryptographic and semantic validation inside `validatePerasCert` before the Peras object-diffusion path is enabled in any deployment:

- Verify the certificate's aggregate signature against the claimed committee members.
- Verify that the signers are eligible committee members for the claimed round (using the stake distribution / VRF sortition).
- Verify that the boosted block's slot falls within the valid range for the certificate's round.

Until proper validation is in place, the object-diffusion inbound handler for Peras certificates should reject all externally supplied certificates rather than forwarding them to `addPerasCertAsync`.

---

### Proof of Concept

1. Run a private-testnet node with Peras enabled.
2. Ensure the node's VolatileDB contains a block `B_fork` on a non-canonical fork.
3. Connect as an unprivileged peer and send a `PerasCert` with `pcCertBoostedBlock = blockPoint B_fork` and any `pcCertRound`.
4. Observe that `processCerts` accepts the certificate (no validation error), `PerasCertDB` stores it, and `chainSelectionForBlock` is invoked for `B_fork`.
5. If `perasWeight params` is large enough relative to the canonical chain's length advantage, the node switches to the non-canonical fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
