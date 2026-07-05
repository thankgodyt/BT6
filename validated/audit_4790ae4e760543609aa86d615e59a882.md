### Title
Stub `validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates, Enabling Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This stub is wired directly into the production node-to-node Peras certificate diffusion handler (`hPerasCertDiffusionClient` in `NodeToNode.hs`). An unprivileged peer can therefore inject arbitrary crafted `PerasCert` objects that are accepted, timestamped, and forwarded to `ChainDB.addPerasCertAsync`, which is documented to trigger a chain-selection fork switch when the boosted block becomes weightier than the current selection.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

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

This is the **only** instance of `BlockSupportsPeras` in the codebase (a blanket instance over all `StandardHash blk`). No per-era override exists yet.

**Inbound processing path — `processCerts` calls the stub:**

`makePerasCertPoolWriterFromChainDB` constructs the inbound pool writer used in production. It passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- stub: always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions results into `(errs, validatedCerts)`. Because `validatePerasCert` always returns `Right`, `errs` is always empty and every peer-supplied certificate is forwarded to `addCert`: [3](#0-2) 

**Production wiring — the handler is unconditionally active:**

`hPerasCertDiffusionClient` in `NodeToNode.hs` calls `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB` for every peer connection, with no feature-flag guard:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [4](#0-3) 

**Chain-selection side-effect — `addPerasCertAsync` can trigger a fork switch:**

The ChainDB API documents the consequence explicitly:

```haskell
, addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [5](#0-4) 

The weight boost assigned to every accepted certificate is `perasWeight params` (from `mkPerasParams`). `chainSelectionForBlock` reads the Peras weight snapshot via `getPerasWeightSnapshot` and passes it to `preferAnchoredCandidate`, which uses it to compare candidate chains: [6](#0-5) 

### Impact Explanation

**Classification:** High — chain-selection bug triggered by an unprivileged peer via a crafted protocol message.

An unprivileged peer connected via the node-to-node Peras certificate diffusion mini-protocol can send a `PerasCert` pointing at any block on any fork. Because `validatePerasCert` performs no validation, the certificate is accepted, stored, and its weight boost is applied to that block in the Peras weight snapshot. If the boosted block is on a competing fork, `addPerasCertAsync` triggers chain selection, and `preferAnchoredCandidate` may now prefer the attacker-chosen fork over the canonical chain. This lets an unprivileged peer steer an honest node away from the canonical chain without needing stake, keys, or any privileged access — matching the "High: chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact category.

The severity is bounded by whether `perasWeight mkPerasParams` is currently non-zero in the deployed configuration; if it is zero the immediate chain-selection effect is suppressed, but the validation bypass remains structurally present and will become exploitable as soon as Peras weight parameters are set to production values.

### Likelihood Explanation

The Peras certificate diffusion handler is unconditionally wired into every node-to-node connection in `mkApps` with no feature flag. Any peer that speaks the `PerasCertDiffusion` mini-protocol can send crafted certificates. No stake, keys, or privileged access is required. The attack requires only knowledge of a competing block's `Point`, which is publicly observable from the chain-sync protocol.

### Recommendation

Replace the stub with a real implementation that verifies committee membership, quorum, and cryptographic signatures before returning `Right`. Until the full implementation is ready, the inbound handler should reject all certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them. Alternatively, gate the `hPerasCertDiffusionClient` handler behind an explicit feature flag that is disabled until Peras validation is complete.

### Proof of Concept

1. Connect to a target node using the node-to-node protocol and negotiate a version that includes the `PerasCertDiffusion` mini-protocol.
2. Observe a competing block `B'` on a fork via ChainSync.
3. Construct a `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(B') }` for any round `r` not already in the node's cert database.
4. Send the certificate via the `PerasCertDiffusion` inbound channel.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` — no rejection.
6. `ChainDB.addPerasCertAsync` is called; if `perasWeight params > 0`, the Peras weight snapshot is updated and `chainSelectionForBlock` re-evaluates candidates, potentially switching to the fork containing `B'`. [7](#0-6) [8](#0-7) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-444)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

```
