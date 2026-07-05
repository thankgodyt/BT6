### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation, Enabling Unauthorized Chain-Selection Weight Injection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Because the production inbound-certificate path in `makePerasCertPoolWriterFromChainDB` calls this stub directly, any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block, have it accepted as "validated", and cause the local node to apply a full Peras weight boost to that block during chain selection — potentially forcing a switch to a non-canonical chain.

### Finding Description

**Root cause — stub validation that always succeeds**

The catch-all instance at `SupportsPeras.hs` lines 318–389 is explicitly labelled a "degenerate instance for all blks to get things to compile":

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

No signature, no committee membership, no round-number bounds, no boosted-block existence check — every `PerasCert` is unconditionally promoted to a `ValidatedPerasCert` carrying the full `perasWeight`.

**Production call path**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` (lines 118–137) is the live inbound handler wired into the ObjectDiffusion mini-protocol. It passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`processCerts` (lines 164–185) calls this callback on every new certificate received from a peer. Because the callback always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`.

`addPerasCertAsync` (ChainSel.hs lines 303–310) enqueues the certificate for chain-selection processing. Chain selection then reads the `PerasWeightSnapshot` — which is updated by the newly accepted certificate — and may switch to the boosted fork.

**Analogous missing check**

The external report describes a function that should enforce "only the marketplace can call this" but omits the guard. Here, `validatePerasCert` should enforce "only a certificate carrying a valid aggregate BLS signature over the correct committee and round may be accepted" but the guard is entirely absent. The structural parallel is exact: a validation boundary that is supposed to be the sole gatekeeper is a no-op.

### Impact Explanation

An unprivileged peer can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the VolatileDB.
2. Send it over the Peras certificate diffusion mini-protocol.
3. The receiving node accepts it unconditionally, stores it in the `PerasCertDB`, and triggers chain selection.
4. Chain selection applies the full `perasWeight` boost to the attacker-chosen block.
5. If the boosted block is on a fork that is otherwise equal-length or slightly shorter than the honest chain, the node switches to that fork.

This constitutes a **bypass of Peras certificate verification** enabling unauthorized chain-selection weight injection. A coordinated attacker sending certificates to multiple nodes can cause them to converge on a non-canonical chain, violating the Peras safety guarantee that only honestly-quorum-certified blocks receive weight boosts.

### Likelihood Explanation

The attack requires only a network connection to a node running the Peras ObjectDiffusion protocol. No keys, no stake, no prior chain knowledge beyond a target block hash (obtainable from the public chain) are needed. The `PerasCert` type is serialisable and its fields are trivially constructable. The only prerequisite is that the target block is not yet immutable (i.e., within the last *k* blocks), which is always true for recent forks.

### Recommendation

Replace the stub with a real implementation that:
1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregate public key of the claimed committee members.
2. Verifies each voter's VRF eligibility proof.
3. Checks that the claimed voters collectively hold stake above the quorum threshold.
4. Checks that `pcCertRound` falls within the expected window relative to the current chain tip.

Until the real implementation is ready, the stub should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the inbound path is safely closed rather than wide open.

### Proof of Concept

```
Attacker node A connects to honest node H via the Peras cert diffusion protocol.

1. A observes block B on a fork F (slot S, hash H_B) from H's ChainSync stream.
2. A constructs:
     cert = PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = BlockPoint S H_B }
3. A sends cert to H via the ObjectDiffusion cert protocol.
4. H's makePerasCertPoolWriterFromChainDB calls processCerts, which calls
     validatePerasCert mkPerasParams cert  =>  Right (ValidatedPerasCert cert fullBoost)
5. H calls addPerasCertAsync, enqueuing the cert.
6. chainSelSync processes the cert; getPerasWeightSnapshot now includes a boost for B.
7. preferAnchoredCandidate now prefers fork F over the honest chain if F's tip
   is at least as long, causing H to switch to F.
```

**Key files and lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
