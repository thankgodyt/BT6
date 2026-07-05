### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gating function that must produce a `ValidatedPerasCert` capability token before a certificate can be added to the ChainDB and influence chain selection. The sole production instance of this typeclass — a universal degenerate instance covering all block types — unconditionally returns `Right` from `validatePerasCert` without performing any cryptographic or structural checks. An unprivileged peer can send a crafted `PerasCert` (containing an arbitrary round number and boosted block point) over the Peras cert diffusion mini-protocol; the node will accept it as fully validated and use it to influence chain selection.

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the required validation gate:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
``` [1](#0-0) 

The only instance in the codebase is the universal degenerate instance, which always returns `Right` regardless of the certificate content:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

This instance is not a test stub — it is the universal instance (`instance StandardHash blk => BlockSupportsPeras blk`) that covers all block types including production Cardano blocks, because no more-specific instance exists. [3](#0-2) 

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes this no-op validator directly to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [4](#0-3) 

`processCerts` partitions results into valid/invalid; since `validatePerasCert` always returns `Right`, every inbound certificate is classified as valid and forwarded to `ChainDB.addPerasCertAsync`: [5](#0-4) 

This writer is wired directly into the live node-to-node handler for the Peras cert diffusion mini-protocol:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound ...
    (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
    ...
``` [6](#0-5) 

The `ValidatedPerasCert` type is the capability token (analogous to the `LiquidateFeature` cap in the external report). The downstream chain-selection code requires this token and trusts it unconditionally. Because `validatePerasCert` always mints the token, the access-control boundary is entirely absent.

### Impact Explanation

An unprivileged peer can send a `PerasCert` containing any `PerasRoundNo` and any `Point blk` (boosted block). The node accepts it as a `ValidatedPerasCert` carrying a full `perasWeight` boost and adds it to the ChainDB, which triggers chain selection. A crafted certificate can boost an attacker-controlled or non-canonical block, causing an honest node to prefer a weaker or adversarial chain over the canonical one. This is a **High** impact chain-selection manipulation: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended Peras security assumptions.

### Likelihood Explanation

The Peras cert diffusion mini-protocol is an active, externally reachable network endpoint wired into every node that enables the feature. No keys, stake, or operator access are required — any peer that can establish a node-to-node connection can send a crafted `PerasCert`. The degenerate instance is the only instance in the codebase, so there is no code path that performs real validation.

### Recommendation

The degenerate `BlockSupportsPeras` instance must not be used in any live network path. Either:
1. Gate the Peras cert diffusion mini-protocol behind a feature flag that is disabled until a proper `BlockSupportsPeras` instance with real BLS aggregate-signature verification (as already implemented in `WFALS.hs` / `EveryoneVotes.hs`) is wired to the Cardano block type; or
2. Remove the universal degenerate instance and require an explicit, validated instance for each concrete block type before the protocol can be activated.

The `ValidatedPerasCert` newtype wrapper provides a false sense of security as long as the function that produces it performs no checks.

### Proof of Concept

1. Establish a node-to-node connection to a target node with the Peras cert diffusion mini-protocol enabled.
2. Send a `PerasCert` message with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a non-canonical block>`.
3. The target node calls `validatePerasCert mkPerasParams cert`, which unconditionally returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. `processCerts` sees no validation errors and calls `ChainDB.addPerasCertAsync` with the crafted certificate.
5. Chain selection runs with the boosted non-canonical block, potentially causing the node to switch away from the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-180)
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
