### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation, Enabling Attacker-Controlled Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Any unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` and `pcCertRound`, have it accepted as valid, and trigger chain selection for the boosted block — directly analogous to the Chainlink oracle accepting an attacker-controlled callback address and executing it without restriction.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The sole production instance — a universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as an unconditional pass-through:

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

No BLS aggregate signature is verified, no voter eligibility proofs are checked, no round-number bounds are enforced, and no boosted-block validity is confirmed. The comment explicitly marks this as a placeholder ("degenerate instance for all blks to get things to compile"). [2](#0-1) 

This stub is wired directly into the production node-to-node handler. `makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams` as the sole validation step before adding a certificate to the `PerasCertDB` and triggering chain selection:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

`processCerts` partitions results into valid/invalid; because `validatePerasCert` always returns `Right`, every certificate lands in the valid bucket and is unconditionally forwarded to `addPerasCertAsync`: [4](#0-3) 

`makePerasCertPoolWriterFromChainDB` is registered as the inbound handler for the Peras certificate diffusion mini-protocol in the production node-to-node stack:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
        ...
        (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
        ...
``` [5](#0-4) 

Once a certificate is accepted, `chainSelSync` in `ChainSel.hs` calls `chainSelectionForBlock` for the boosted block, potentially switching the node's preferred chain: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` with:
- `pcCertRound` set to any round number
- `pcCertBoostedBlock` set to the hash of any block the attacker wants to boost

Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to inflate the Peras chain weight of the attacker-chosen block. This can cause the honest node to prefer a fork that it would otherwise reject, constituting a **bypass of Peras certificate checks that enables unauthorized certificate acceptance** and a **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain**.

This is the direct analog of the Chainlink oracle blindly executing `callback.addr.call(callback.functionId, ...)` with attacker-supplied parameters: here the "callback" is `validatePerasCert`, the "attacker-controlled address" is `pcCertBoostedBlock`, and the "privileged side-effect" is chain selection.

---

### Likelihood Explanation

The attack requires only a valid node-to-node connection. No stake, no keys, no admin access. The Peras certificate diffusion mini-protocol is open to any peer that completes the handshake. The crafted certificate needs only to be CBOR-decodable as a `PerasCert` (two fields: a round number and a block point), which is trivial to construct.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` before any production deployment of Peras. At minimum, verify the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set, and verify each voter's eligibility proof against the committee selection data for that round.
2. **Remove the universal stub instance** (`instance StandardHash blk => BlockSupportsPeras blk`) or gate it behind a compile-time flag that is disabled for production builds, so that any block type lacking a real implementation fails to compile rather than silently accepting all certificates.
3. **Pass real committee/stake-distribution data** into `makePerasCertPoolWriterFromChainDB` instead of `mkPerasParams` (a placeholder), mirroring the pattern already used for vote validation where `getStakeDistrSTM` is threaded through.

---

### Proof of Concept

1. Connect to a node running the Peras certificate diffusion mini-protocol.
2. Construct a CBOR-encoded `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of a fork block>`.
3. Send it via the `ObjectDiffusion` inbound protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. `ChainDB.addPerasCertAsync` stores the certificate; `chainSelSync` calls `chainSelectionForBlock` for the boosted fork block.
6. The node's chain selection now accounts for the fabricated Peras weight boost, potentially switching to the attacker-chosen fork.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
