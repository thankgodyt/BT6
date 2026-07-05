### Title
Peras Certificate Verification Bypass via Stub `validatePerasCert` Unconditionally Returning `Right` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no actual cryptographic or structural validation. This is the direct analog of the ERC20 silent-failure pattern: instead of a return value being ignored, the validation function itself never returns `Left`, so every inbound certificate from an unprivileged peer is silently accepted as valid. Because accepted certificates are fed into `addPerasCertAsync` and trigger Peras weight-boosted chain selection, an attacker can inject arbitrary certificates to manipulate which chain the node prefers.

---

### Finding Description

**Root cause — stub validation that always succeeds:**

In `SupportsPeras.hs`, the only concrete `BlockSupportsPeras` instance (the universal one, gated only on `StandardHash blk`) implements `validatePerasCert` as:

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

This function never returns `Left`. No signature is checked, no round number is validated against the current epoch, no boosted-block point is verified to exist or be on a valid chain, and no quorum proof is verified. The `PerasValidationErr` data type is itself a stub with a single constructor and no fields:

```haskell
data PerasValidationErr blk
  = PerasValidationErr
  deriving stock (Show, Eq)
``` [2](#0-1) 

**Attacker-controlled entry path:**

Inbound Peras certificates arrive from peers via the object-diffusion miniprotocol. `makePerasCertPoolWriterFromChainDB` is the production writer used for peer-received certificates. It calls `processCerts`, which calls `validatePerasCert mkPerasParams` on each certificate not already in the DB:

```haskell
(validatePerasCert mkPerasParams)
-- We do not want to block the writer thread on waiting for ChainSel
-- side-effects to complete, so we use the async version of adding
-- certs to the ChainDB and ignore the returned promise.
(void . ChainDB.addPerasCertAsync chainDB)
``` [3](#0-2) 

`processCerts` partitions results with `partitionEithers`. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is passed to `addCert`: [4](#0-3) 

`addPerasCertAsync` enqueues the certificate for the ChainDB background thread, which applies the `vpcCertBoost` weight to the boosted block during chain selection: [5](#0-4) 

**Compounding issue — promise result also discarded:**

The `AddPerasCertPromise` returned by `addPerasCertAsync` is discarded with `void`, so the inbound handler has no way to observe whether the certificate was rejected as too old (`PerasCertIgnoredTooOld`) or whether chain selection actually ran. This mirrors the ERC20 pattern exactly: the return value carrying outcome information is thrown away. [6](#0-5) 

---

### Impact Explanation

**Impact: High — chain selection manipulation via bypass of Peras certificate verification.**

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is added to the weight of the `pcCertBoostedBlock` during chain selection. By injecting a crafted certificate pointing to any block already present in the node's VolatileDB (e.g., a block on a minority fork), an attacker can cause the node to assign extra Peras weight to that fork and switch away from the honest canonical chain. This satisfies the "High" impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

The attacker does not need to forge blocks or hold any stake. They only need a peer connection and knowledge of a block hash present in the target node's VolatileDB.

---

### Likelihood Explanation

**Likelihood: Medium.**

The Peras object-diffusion miniprotocol is active in the production node. Any peer that can establish a connection can send `PerasCert` messages. The stub is the only `BlockSupportsPeras` instance in the codebase (the comment explicitly calls it a "degenerate instance for all blks to get things to compile"). The attack requires no special privileges, no key material, and no stake. The only mitigating factor is that Peras is still being deployed and the weight boost magnitude depends on `perasWeight params`; if that value is small relative to chain density, the practical impact on chain selection may be limited in some configurations.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras miniprotocol is enabled on any network. At minimum, verify: (a) the certificate's aggregate signature over the claimed quorum of votes, (b) that the boosted block point exists and is within the valid Peras boost window, and (c) that the round number is consistent with the current epoch.
2. **Do not use the stub instance in production.** Gate the `BlockSupportsPeras` instance on a concrete era type (e.g., a future Conway/Peras era) rather than the universal `StandardHash blk` constraint, so the type system prevents the stub from being used with real blocks.
3. **Check the `AddPerasCertPromise` result** in `makePerasCertPoolWriterFromChainDB` rather than discarding it with `void`, so that failures (e.g., `PerasCertNotProcessedClosing`) are observable and can be logged or used to disconnect misbehaving peers.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node with Peras enabled and the object-diffusion miniprotocol active.
2. Observe a block hash `H` on a minority fork present in the node's VolatileDB (obtainable via the ChainSync miniprotocol).
3. Connect to the node as a peer and send a `PerasCert` message with `pcCertBoostedBlock = H` and any `pcCertRound`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=perasWeight mkPerasParams}` unconditionally.
5. `addPerasCertAsync` enqueues the cert; the ChainDB background thread applies the weight boost to block `H`.
6. If the boosted weight of the fork containing `H` now exceeds the weight of the current selection, the node switches to that fork.

The deterministic root cause is at:
- `SupportsPeras.hs` lines 350–358: `validatePerasCert` always returns `Right`.
- `PerasCert.hs` lines 126, 132: the stub validator is called and its result (always `Right`) is used to unconditionally add the cert. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L604-613)
```haskell
data AddPerasCertChainSelOutcome
  = -- | The certificate was too old to influence chain selection (the boosted
    -- block is already immutable), so it was ignored entirely.
    PerasCertIgnoredTooOld
  | -- | The certificate was not processed because the ChainDB was closing.
    PerasCertNotProcessedClosing
  | -- | The certificate was processed; whether it was actually added to the DB
    -- or was a duplicate is captured by the inner 'AddPerasCertResult'.
    PerasCertProcessed AddPerasCertResult
  deriving stock (Generic, Eq, Ord, Show)
```
