### Title
`validatePerasCert` Always Returns `Right` Without Performing Any Validation, Enabling Unauthorized Peras Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic, committee-membership, or structural checks. Because this is the sole validation gate called by the production certificate-ingest path (`processCerts`), any unprivileged peer can inject arbitrary Peras certificates that are accepted without question and subsequently used to influence chain selection.

---

### Finding Description

`BlockSupportsPeras` is a type class whose `validatePerasCert` method is supposed to authenticate an inbound `PerasCert` before it is stored and acted upon. The only instance in the codebase is a blanket `instance StandardHash blk => BlockSupportsPeras blk` that is explicitly labelled a "degenerate instance … to get things to compile":

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

The function body ignores every field of `cert` and returns a fully-constructed `ValidatedPerasCert` carrying the configured boost weight. No signature, no committee-membership check, no round-number sanity check — nothing. [1](#0-0) 

This stub is wired directly into both production pool-writer constructors:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` — the function that calls the validator — is designed to reject the entire batch and disconnect from the peer if *any* certificate fails validation. Because `validatePerasCert` never returns `Left`, the rejection branch is dead code and every certificate is accepted:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _)            -> throw (PerasCertValidationError errs)
``` [3](#0-2) 

Accepted certificates are forwarded to `ChainDB.addPerasCertAsync`, which triggers `chainSelSync`. There, a certificate whose boosted block is in the VolatileDB causes an immediate re-run of chain selection, with the certificate's `vpcCertBoost` weight (`perasWeight = 15` from `mkPerasParams`) added to the candidate chain's density: [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and any round number, send it over the Peras object-diffusion mini-protocol, and have it unconditionally accepted. The accepted certificate immediately re-triggers chain selection with an artificial `+15`-block boost on the attacker's chosen block. This can cause an honest node to:

1. **Prefer a non-canonical or adversarially-chosen chain** over the honest chain, constituting a chain-selection safety failure.
2. **Accept a certificate for a block the attacker controls**, giving that block a persistent weight advantage that survives across subsequent chain-selection rounds.

This matches the **Critical** impact class: bypass of Peras certificate validation that enables unauthorized certificate acceptance and chain-selection manipulation by an unprivileged peer.

---

### Likelihood Explanation

The attack requires only the ability to connect to a node and send a well-formed (but cryptographically unauthenticated) `PerasCert` message over the object-diffusion mini-protocol — no keys, no stake, no operator access. The vulnerable code path is active whenever Peras certificate diffusion is enabled. The `TODO` comment and linked issue confirm the stub is intentional scaffolding that was never replaced with real validation before the code was merged.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:

1. The certificate's cryptographic signature against the claimed committee members.
2. That the signers are eligible committee members for the claimed round (committee-selection check).
3. That the aggregate stake of the signers meets the quorum threshold (`perasQuorumStakeThreshold`).
4. That the round number is within the acceptable window relative to the current tip.

Until real validation is implemented, the production pool-writer constructors (`makePerasCertPoolWriterFromCertDB`, `makePerasCertPoolWriterFromChainDB`) should not be deployed on any network where certificate injection could influence chain selection.

---

### Proof of Concept

1. Connect to a target node that has Peras certificate diffusion enabled.
2. Send a `PerasCert` message with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of an adversarial block in the VolatileDB>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
4. The certificate is stored in `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
5. `chainSelSync` re-runs chain selection for the boosted block; the adversarial chain now carries an extra weight of 15, potentially making it preferred over the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
