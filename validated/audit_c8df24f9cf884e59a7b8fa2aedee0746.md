### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection — (`Ouroboros/Consensus/Block/SupportsPeras.hs`, `ObjectPool/PerasCert.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives. The production inbound cert-diffusion writer (`makePerasCertPoolWriterFromChainDB`) calls this stub directly. Any peer that can speak the Peras cert object-diffusion miniprotocol can therefore inject a certificate for an arbitrary block on any fork, have it stored in the `PerasCertDB`, and trigger `addPerasCertAsync` → `chainSelSync`, causing the node to durably prefer the adversarially boosted fork.

---

### Finding Description

**Root cause — the stub validator:** [1](#0-0) 

The `BlockSupportsPeras` instance is explicitly labelled a "degenerate instance for all blks to get things to compile": [2](#0-1) 

`validatePerasCert params cert` ignores every field of `cert` and every field of `params` (committee membership, BLS/VRF proof, round constraints, quorum threshold) and always returns:
```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```
`perasWeight mkPerasParams` is hardcoded to `PerasWeight 15`.

**Root cause — the production writer uses the stub:** [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` — the writer used in production — passes `validatePerasCert mkPerasParams` as the validator and `ChainDB.addPerasCertAsync chainDB` as the storage/chain-selection trigger. Both are marked `-- TODO replace when actual plumbing is in place`.

**Root cause — `processCerts` trusts the validator's result:** [4](#0-3) 

`processCerts` calls `validateCert` on every cert not already in the DB. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is stored and forwarded to `addCert`.

**The `PerasCert` data type carries no cryptographic proof:** [5](#0-4) 

`PerasCert blk` contains only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`. There is no committee proof, no BLS aggregate signature, no VRF output — so a peer can trivially construct a well-typed cert for any block.

**Inbound path — no additional guard:** [6](#0-5) 

`opwAddObjects objectsToAck` is the sole call that hands received objects to the pool writer. There is no secondary validation layer between the network receipt and `processCerts`.

---

### Impact Explanation

An unprivileged peer sends a `PerasCert` pointing to a block on a minority fork. The cert passes `validatePerasCert mkPerasParams` (stub, always `Right`), is stored in `PerasCertDB`, and `addPerasCertAsync` fires `chainSelSync`. Chain selection adds `PerasWeight 15` to the boosted block's chain weight. If the fork's natural weight plus 15 exceeds the current chain's weight, the node irreversibly switches to the adversarially boosted fork and maintains it. The resulting ledger state is wrong and durable (survives restart via the stored cert).

This matches the **High** scope: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions"* and *"ChainDB … corruption … that causes durable use of the wrong ledger state … without operator fault."*

---

### Likelihood Explanation

The attack requires only that the Peras cert object-diffusion miniprotocol is negotiated between peers. The cert payload is trivially constructable (two integers / a point). No key material, stake, or special privilege is needed. The only precondition is that the target node has the boosted fork's block in its `VolatileDB` (easily arranged by first sending the block via BlockFetch). Likelihood is **High** once the miniprotocol is enabled in production.

---

### Recommendation

1. **Do not enable the Peras cert object-diffusion miniprotocol in production** until `validatePerasCert` performs real cryptographic validation (committee membership proof, aggregate BLS/VRF signature, round and quorum constraints).
2. Replace the degenerate `BlockSupportsPeras` instance with a proper per-era implementation before the protocol is negotiated.
3. Add a compile-time or runtime guard (e.g., a feature flag checked at miniprotocol negotiation) that prevents the cert-diffusion handler from being wired up when the stub is in place.
4. Track the referenced issues (`tweag/cardano-peras#73`, `#120`) as security-blocking before any production rollout.

---

### Proof of Concept

```haskell
-- Construct a cert for a block on a fork (no crypto needed):
let fakeCert = PerasCert
      { pcCertRound      = PerasRoundNo 42
      , pcCertBoostedBlock = forkBlockPoint  -- any Point blk
      }

-- validatePerasCert mkPerasParams fakeCert
-- => Right (ValidatedPerasCert { vpcCert = fakeCert, vpcCertBoost = PerasWeight 15 })
-- (stub, SupportsPeras.hs lines 353-358)

-- processCerts will store it and call addPerasCertAsync,
-- triggering chainSelSync with +15 weight on forkBlockPoint.
```

A unit test asserting `isLeft (validatePerasCert mkPerasParams certWithInvalidCommitteeProof)` would fail on the current code, confirming the invariant is broken.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L404-411)
```haskell
            objectsToAck =
              catMaybes $
                (((Map.!) pendingObjects') <$> toList objectIdsToAck)

        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))
```
