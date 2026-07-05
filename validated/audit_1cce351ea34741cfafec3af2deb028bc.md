### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inject Arbitrary Certificates and Manipulate Chain Selection - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

### Summary
The production `validatePerasCert` implementation is a stub that unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural checks. This stub is wired directly into the live certificate-diffusion ingest path. Any unprivileged peer can therefore inject a crafted `PerasCert` with an arbitrary boosted-block pointer, causing the receiving node to apply the configured Peras chain-weight boost to a block of the attacker's choosing and potentially switch to an adversarial fork.

### Finding Description

**Root cause — always-`Right` validator stub**

`validatePerasCert` in the degenerate `BlockSupportsPeras` instance unconditionally returns `Right` for every certificate it receives:

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

No quorum check, no cryptographic signature verification, and no structural invariant is enforced. The `PerasValidationErr` data type is itself a single-constructor placeholder with no fields:

```haskell
data PerasValidationErr blk
  = PerasValidationErr
  deriving stock (Show, Eq)
``` [2](#0-1) 

**Production ingest path uses the stub**

`makePerasCertPoolWriterFromChainDB` — the production writer used by the live node — passes `validatePerasCert mkPerasParams` as the sole validator inside `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` calls `validateCert` on every certificate not already in the DB and, if all pass, stores them and calls `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because the validator always returns `[]` errors, every certificate is stored.

**Chain-selection consequence**

`makePerasCertPoolWriterFromChainDB` routes accepted certificates into `ChainDB.addPerasCertAsync`, which triggers `chainSelSync`. Chain selection then applies the `perasWeight` boost (default **15 blocks**) to whichever block `pcCertBoostedBlock` points to:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

The `perasCertDiffusionProtocol` mini-protocol is included in the node-to-node protocol bundle and is reachable by any connecting peer: [6](#0-5) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` whose `pcCertBoostedBlock` points to any block hash present in the target node's VolatileDB. The node will apply a weight of `perasWeight = 15` to that block during chain selection. If the attacker also serves a valid competing fork (which any peer can do via BlockFetch), the artificial boost can cause the honest node to prefer the adversarial fork over the canonical chain — a chain-selection manipulation that violates the Peras safety guarantee. This maps to the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

### Likelihood Explanation

The `perasCertDiffusionProtocol` is active in the node-to-node protocol bundle. Any peer that can open a connection can send crafted certificates. No stake, keys, or privileged access are required. The only precondition is that the target block hash is already in the node's VolatileDB, which is trivially satisfied by first sending the block via BlockFetch. Likelihood is **High**.

### Recommendation

Replace the stub with a real implementation that:
1. Verifies the aggregate cryptographic signature over the quorum of votes embedded in the certificate.
2. Checks that the number of signers and their combined stake meet the `perasQuorumStakeThreshold`.
3. Validates that `pcCertBoostedBlock` refers to a block within the allowed age window (`perasCertMaxRounds`).
4. Rejects certificates whose `pcCertRound` is outside the valid range relative to the current slot.

Until the real implementation is ready, the ingest path should reject all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all.

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the node-to-node protocol.
2. Serve a valid competing block `B_adv` (fork depth ≤ 14 from the honest tip) via BlockFetch so it enters the node's VolatileDB.
3. Construct a `PerasCert` with `pcCertBoostedBlock = blockPoint B_adv` and any `pcCertRound`.
4. Send the certificate via the `perasCertDiffusionProtocol` mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
6. The certificate is stored; `chainSelSync` fires and applies a weight of 15 to `B_adv`.
7. Chain selection now prefers the adversarial fork, causing the node to roll back up to 14 honest blocks and adopt `B_adv`'s chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-342)
```haskell
  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1214-1215)
```haskell
        , perasCertDiffusionProtocol =
            (InitiatorProtocolOnly (MiniProtocolCb (\ctx -> aPerasCertDiffusionClient version ctx)))
```
