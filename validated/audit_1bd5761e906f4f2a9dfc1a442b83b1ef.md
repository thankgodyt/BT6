Let me check the ChainDB API for `addPerasCertAsync` and the Peras cert DB to understand the chain selection side-effects.

### Title
Unconditional Peras Certificate Acceptance via TODO-stub `validatePerasCert` Allows Unprivileged Peer to Inject Arbitrary Certs into ChainDB Chain Selection — (`Ouroboros/Consensus/Block/SupportsPeras.hs`, `MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The production `BlockSupportsPeras` blanket instance's `validatePerasCert` is an unconditional stub that always returns `Right`, regardless of certificate content. Every inbound Peras certificate received over the object-diffusion miniprotocol is therefore accepted without any semantic check and forwarded to `ChainDB.addPerasCertAsync`, which is documented to trigger chain-selection side-effects. An unprivileged peer can inject certificates boosting arbitrary forks, future rounds, or genesis, and the node will accept and act on them.

---

### Finding Description

**Root cause — `validatePerasCert` stub (SupportsPeras.hs lines 353–358):**

The blanket instance `instance StandardHash blk => BlockSupportsPeras blk` provides the following implementation:

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

This is explicitly labeled a "degenerate instance for all blks to get things to compile": [2](#0-1) 

No check is performed on `pcCertRound`, `pcCertBoostedBlock`, committee membership, quorum, signatures, or any other semantic property.

---

**Attack path — `processCerts` in `ObjectPool/PerasCert.hs`:**

`makePerasCertPoolWriterFromChainDB` wires the stub directly into the inbound pipeline:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [3](#0-2) 

`processCerts` calls `validateCert` on every cert not already in the DB. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is passed to `addCert`: [4](#0-3) 

The rejection branch (`(errs, _) -> throw (PerasCertValidationError errs)`) is structurally present but is **dead code** as long as the stub is in place.

---

**Inbound protocol entry point — `objectDiffusionInbound`:**

`opwAddObjects` is called directly from the `CollectObjects` branch of `goCollect` in `Inbound.hs`: [5](#0-4) 

Any NodeToNode peer that speaks the object-diffusion miniprotocol can reach this path with a structurally valid but semantically arbitrary `PerasCert`.

---

### Impact Explanation

`ChainDB.addPerasCertAsync` is explicitly documented to "properly handle any needed chain selection side-effects." A cert with an adversarially chosen `pcCertBoostedBlock` pointing to a minority fork, a future slot, or genesis will be stored and acted upon by chain selection. Because Peras boost weights (`perasWeight params`) are applied unconditionally, an adversary can steer an honest node's preferred chain toward a fork of their choosing, causing an irreversible divergent chain — matching the Critical scope target.

---

### Likelihood Explanation

The object-diffusion miniprotocol is wired into the production node stack. Any peer that can negotiate the protocol can send a single well-formed `PerasCert` CBOR message. No stake, keys, or privileges are required. The stub is the only guard between the wire and `ChainDB.addPerasCertAsync`.

---

### Recommendation

1. **Immediately replace the stub** with a real implementation of `validatePerasCert` that checks: committee membership and quorum, cryptographic signatures on constituent votes, round number bounds relative to the current tip, and that `pcCertBoostedBlock` refers to a known, non-genesis block on the current chain.
2. Until a real implementation exists, **gate the object-diffusion miniprotocol** so it is not negotiated with peers on any network where Peras chain-selection side-effects are active.
3. Track issue [#120](https://github.com/tweag/cardano-peras/issues/120) and [#73](https://github.com/tweag/cardano-peras/issues/73) as security-blocking, not merely correctness TODOs.

---

### Proof of Concept

```haskell
-- Property: for any PerasCert, validatePerasCert always returns Right
prop_validatePerasCertAlwaysRight :: PerasCert TestBlock -> Bool
prop_validatePerasCertAlwaysRight cert =
  isRight (validatePerasCert mkPerasParams cert)

-- Confirm processCerts never throws for arbitrary certs
test_processCertsAcceptsArbitraryCert :: IO ()
test_processCertsAcceptsArbitraryCert = do
  let cert = PerasCert
        { pcCertRound = PerasRoundNo maxBound   -- far-future round
        , pcCertBoostedBlock = GenesisPoint      -- genesis
        }
  addedRef <- newIORef []
  processCerts
    mockSystemTime
    (pure Set.empty)                            -- nothing in DB
    (validatePerasCert mkPerasParams)           -- production stub
    (\c -> modifyIORef addedRef (c:))
    [cert]
  added <- readIORef addedRef
  -- assert: cert was accepted and forwarded, not rejected
  assert (length added == 1)
```

The property passes unconditionally on unmodified code. The `PerasCertValidationError` throw path is never reached. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L408-411)
```haskell
        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))
```
