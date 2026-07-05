### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or semantic checks. This stub is wired directly into the live Peras certificate ingest pipeline (`processCerts`), which is reachable from any unprivileged network peer via the object-diffusion mini-protocol. Because validation always succeeds, a peer can inject crafted certificates that boost arbitrary blocks in chain selection, causing honest nodes to prefer non-canonical chains.

---

### Finding Description

**Root cause — unconditional success in `validatePerasCert`:**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) implements `validatePerasCert` as:

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

This is the exact structural analog of the MintbaseStore bug: the consequential action (accepting the certificate as `ValidatedPerasCert`) happens unconditionally, outside any conditional check, regardless of whether the certificate is cryptographically or semantically valid.

**Exploit path — `processCerts` in the live ingest pipeline:**

`validatePerasCert mkPerasParams` is passed as the `validateCert` callback to `processCerts` in the `ObjectPoolWriter` for Peras certificates:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

Inside `processCerts`, the validation result is branched on via `partitionEithers`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validateCert` always returns `Right`, `partitionEithers` always produces `([], validatedCerts)` — the rejection branch is structurally unreachable. Every certificate from every peer is unconditionally accepted and added to `PerasCertDB` via `ChainDB.addPerasCertAsync`.

**Chain selection consequence:**

Accepted certificates are stored in `PerasCertDB` and their boosts are reflected in `getWeightSnapshot`, which is consumed by chain selection. The `totalWeightOfFragment` function adds `weightBoostOfFragment` (derived from the cert DB) to the raw chain length when comparing candidates: [4](#0-3) 

An attacker who injects a certificate boosting a block on a shorter, adversarial fork can make that fork's `totalWeightOfFragment` exceed the honest chain's, causing `chainSelectionForBlock` to switch to the adversarial chain. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block hash. Because `validatePerasCert` never rejects, the certificate is accepted, stored, and its boost is applied to chain selection. This allows the attacker to make an honest node prefer a non-canonical or adversarially-controlled chain, violating chain selection safety. This maps to the **High** impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions"*, and also to the **Critical** category: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is live and reachable from any connected peer without any privilege requirement. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` message. No key material, stake, or operator access is needed. The only rate-limiting factor is the per-round deduplication check (`Set.member roundNo certIds`), which an attacker can trivially bypass by using a fresh `pcCertRound` value for each injected certificate.

---

### Recommendation

Replace the stub with a real implementation that verifies the certificate's cryptographic proof (aggregate BLS signature over the election ID and candidate block), checks that the declared voters hold sufficient stake to meet `perasQuorumStakeThreshold`, and validates that `pcCertRound` and `pcCertBoostedBlock` are within the permitted age window (`perasCertMaxRounds`). Until the real implementation is in place, `validatePerasCert` should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the ingest pipeline is safely inert rather than unconditionally permissive.

---

### Proof of Concept

1. Connect to a target node as a normal peer via the Peras object-diffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the tip of an adversarial fork that is shorter than the honest chain
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}` unconditionally.
4. `partitionEithers` produces `([], [validatedCert])`, so `addCert` is called and the certificate enters `PerasCertDB`.
5. `getWeightSnapshot` now includes a boost for the adversarial fork's tip.
6. On the next chain selection event, `totalWeightOfFragment` for the adversarial fork equals its length plus `perasWeight`, which can exceed the honest chain's length, causing the node to switch to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
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
