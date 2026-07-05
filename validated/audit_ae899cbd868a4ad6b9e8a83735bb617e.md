### Title
Unconditional Peras Certificate Acceptance Enables Unauthorized Chain-Selection Weight Boost by Any Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted target; the certificate passes "validation", is inserted into the ChainDB, and triggers a Peras weight boost that can cause the victim node to prefer a non-canonical chain over the honest chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The universal instance for `BlockSupportsPeras blk` in `SupportsPeras.hs` implements `validatePerasCert` as:

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

Every certificate, regardless of content, is wrapped in `Right` and stamped with the full Peras weight boost. No committee membership check, no BLS aggregate signature verification, no round-number plausibility check, and no boosted-block existence check is performed. [1](#0-0) 

**Inbound path — any peer reaches `validatePerasCert`:**

`makePerasCertPoolWriterFromChainDB` is the production writer used when the Peras object-diffusion mini-protocol receives certificates from remote peers. It passes `validatePerasCert mkPerasParams` directly as the validation callback:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

**`processCerts` — the gate that never closes:**

`processCerts` calls `validateCert` on each new certificate and adds all that return `Right`. Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable; every certificate from every peer is unconditionally forwarded to `ChainDB.addPerasCertAsync`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)   -- never reached
``` [3](#0-2) 

**Chain-selection consequence:**

`addPerasCertAsync` enqueues the certificate for processing by `chainSelSync`, which reads the Peras weight snapshot from `PerasCertDB` and uses it in `preferAnchoredCandidate` to compare candidate chains. A certificate boosting block `B` adds `vpcCertBoost` (= `perasWeight params`) to `B`'s chain weight, potentially making a shorter or non-canonical fork preferred over the honest chain. [4](#0-3) [5](#0-4) 

**Analog to the external report:**

The external report describes `createPosition()` accepting calls from any address because the authorization check is absent. Here, `validatePerasCert` is the authorization check for Peras certificates — it is structurally present but permanently disabled (always `Right`), so any peer can inject a certificate for any block, exactly as any address could call `createPosition()`.

### Impact Explanation

**Impact: High — Bypass of Peras certificate validation enabling unauthorized chain-selection weight boost.**

A single malicious peer can inject a `PerasCert` naming any block it chooses as the boosted target. The victim node will apply the full Peras weight boost to that block during chain selection. If the attacker targets a block on a minority fork (or a block the attacker itself produced), the victim node may switch away from the honest majority chain to the attacker-boosted fork. This violates the Peras chain-selection invariant that only legitimately certified blocks (backed by a quorum of committee BLS signatures) receive weight boosts, and can cause the node to permanently adopt a non-canonical chain.

### Likelihood Explanation

**Likelihood: High.** The Peras object-diffusion mini-protocol is a standard NTN connection reachable by any peer without authentication. The attacker needs only to:
1. Connect to the victim node as a normal peer.
2. Craft a `PerasCert` CBOR payload with an arbitrary `pcCertRound` and `pcCertBoostedBlock`.
3. Send it via the Peras cert diffusion channel.

No keys, no stake, no privileged access are required. The only partial mitigation is the deduplication check (`Set.member roundNo alreadyInDb`), which prevents re-injection of a certificate for a round already seen — but the first injection per round succeeds unconditionally.

### Recommendation

1. **Implement real `validatePerasCert`**: verify the aggregate BLS signature against the committee's public keys, check that the signer set meets the quorum threshold, and confirm the boosted block exists on a known chain fragment before accepting the certificate.
2. **Block the inbound path until validation is complete**: the `-- TODO replace when actual plumbing is in place` comment in `makePerasCertPoolWriterFromChainDB` must be resolved before the Peras diffusion mini-protocol is enabled on any network that uses Peras weight in chain selection.
3. **Add a guard in `processCerts`**: if the supplied `validateCert` function is known to be a stub (e.g., during development), reject all inbound certificates rather than accepting them all.

### Proof of Concept

```
-- Attacker connects as a normal NTN peer and sends a crafted PerasCert CBOR message:
--
--   PerasCert { pcCertRound = <any new round>, pcCertBoostedBlock = <attacker-chosen block point> }
--
-- processCerts calls validatePerasCert mkPerasParams on the cert.
-- validatePerasCert unconditionally returns:
--   Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })
--
-- The cert is forwarded to ChainDB.addPerasCertAsync.
-- chainSelSync reads the updated PerasWeightSnapshot, which now includes a boost
-- for the attacker-chosen block.
-- preferAnchoredCandidate uses this boost; if the boosted fork is otherwise
-- equal-length or close to the current chain, the node switches to it.
--
-- No cryptographic material, no stake, no committee membership required.
```

The degenerate `validatePerasCert` implementation is at: [6](#0-5) 

The production inbound writer that wires it to the live ChainDB is at: [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
