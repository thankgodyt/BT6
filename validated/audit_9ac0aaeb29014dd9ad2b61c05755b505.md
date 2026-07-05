### Title
Peras Certificate Validation Bypass Allows Any Peer to Inject Arbitrary Certificates and Manipulate Chain Selection — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) without performing any cryptographic or committee-membership checks. This stub is wired directly into the production certificate ingestion path. Any unprivileged peer can send a crafted `PerasCert` that will be accepted, stored, and used to trigger chain selection for an arbitrary block, enabling chain-selection manipulation.

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must verify a Peras certificate before it is admitted to the node's state. The universal instance — explicitly marked as a temporary degenerate instance "for all blks to get things to compile" — implements this gate as:

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

This stub is the implementation used in the production certificate ingestion path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` directly to `processCerts` as the validation callback:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` applies this callback to every inbound certificate not already in the database. Because the callback always returns `Right`, every certificate passes:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Accepted certificates are forwarded to `addPerasCertAsync`, which enqueues them for chain selection processing:

```haskell
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
``` [4](#0-3) 

Chain selection then triggers `chainSelectionForBlock` for the block named in the certificate's `pcCertBoostedBlock` field, giving it an additional weight of `perasWeight` (15 by default): [5](#0-4) 

The `ValidatedPerasCert` wrapper — which is supposed to be a type-level proof of legitimacy — is produced unconditionally from any raw `PerasCert`, so the type system provides no protection once the stub is in place. [6](#0-5) 

### Impact Explanation

**High — Chain selection manipulation.** When Peras is enabled, an attacker can inject a `PerasCert` that names any block in the node's VolatileDB as the boosted block. The certificate is accepted without any signature or quorum check, stored in the `PerasCertDB`, and immediately used to re-run chain selection with the boosted block receiving +15 weight. By targeting a block on a non-canonical fork, the attacker can cause the honest node to prefer that fork over the canonical chain, constituting a chain-selection safety failure beyond the intended Peras security assumptions.

### Likelihood Explanation

Any peer connected via the object diffusion mini-protocol can send `PerasCert` messages. No stake, keys, or special privileges are required. The attack requires only knowledge of a block hash present in the target node's VolatileDB (obtainable via ChainSync). The attack is trivially repeatable for every round.

### Recommendation

Implement real cryptographic validation inside `validatePerasCert`: verify that the certificate carries valid aggregate signatures from a quorum of eligible committee members for the claimed round, using the stake distribution and committee selection scheme. Until this is done, the `ValidatedPerasCert` wrapper provides a false type-level guarantee of legitimacy. The upstream tracking issue is https://github.com/tweag/cardano-peras/issues/120. [7](#0-6) 

### Proof of Concept

1. Attacker connects to a Peras-enabled node as a peer via the object diffusion mini-protocol.
2. Attacker learns the hash of a block on a non-canonical fork (e.g., via ChainSync) and constructs:
   ```
   PerasCert { pcCertRound = r, pcCertBoostedBlock = <fork tip point> }
   ```
3. Attacker sends the crafted certificate to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..}` unconditionally.
5. The certificate is stored in `PerasCertDB` and forwarded to `addPerasCertAsync`.
6. `chainSelSync` triggers `chainSelectionForBlock` for the fork tip, which now carries +15 weight.
7. If the boosted fork's cumulative weight exceeds the honest chain's weight, the node switches to the non-canonical fork — a chain-selection safety failure caused entirely by a peer-supplied, unvalidated certificate. [1](#0-0) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
