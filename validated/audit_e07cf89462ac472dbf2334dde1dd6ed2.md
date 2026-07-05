### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Unauthorized Peras Certificates into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate, performing no cryptographic or semantic checks. This stub is wired directly into the live Peras certificate diffusion miniprotocol handler. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted block pointer; the node will accept it as valid, store it in the `PerasCertDB`, and trigger chain selection with the attacker-chosen block receiving the full Peras weight boost, potentially causing the node to prefer a non-canonical chain.

### Finding Description

**Root cause — stub validation always succeeds:**

The sole production `BlockSupportsPeras` instance (the "degenerate instance for all blks") implements `validatePerasCert` as:

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

No BLS aggregate signature is verified, no committee membership is checked, no round-number bounds are enforced, and no boosted-block existence is confirmed. Every certificate, regardless of content or origin, is wrapped in `ValidatedPerasCert` and returned as `Right`.

**Wiring into the production network handler:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`:

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
```

This writer is installed as the inbound handler for the `hPerasCertDiffusionClient` miniprotocol in `mkHandlers`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
```

**Exploit path through `processCerts`:**

`processCerts` calls `validateCert` on each inbound certificate. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch always takes the "all certs are valid" path and calls `addCert . WithArrivalTime now` for every certificate:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

`addCert` resolves to `void . ChainDB.addPerasCertAsync chainDB`, which enqueues a `ChainSelAddPerasCert` message. The background `addBlockRunner` processes this via `chainSelSync`, which applies the `vpcCertBoost` weight (15 blocks, from `perasWeight mkPerasParams`) to the attacker-specified `pcCertBoostedBlock` during chain selection.

### Impact Explanation

An unprivileged peer connected via the Peras certificate diffusion miniprotocol can send a `PerasCert` naming any block as `pcCertBoostedBlock`. The receiving node will:

1. Accept the certificate without any cryptographic check.
2. Store it in the `PerasCertDB` under the attacker-chosen `pcCertRound`.
3. Trigger chain selection, where the attacker-chosen block receives a weight boost of 15 block-equivalents.
4. Potentially switch away from the canonical chain to a fork that includes the attacker-chosen block, if that fork's total weight (including the injected boost) exceeds the current selection.

This constitutes an unauthorized Peras certificate acceptance that can cause an honest node to prefer a non-canonical or adversarially-chosen chain, directly undermining the chain-selection security guarantee that Peras is designed to strengthen.

**Severity: High** — matches "Bypass of... certificate... checks... that enables unauthorized... certificate acceptance" and "Chain selection... bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."

### Likelihood Explanation

**High.** The attack requires only a standard peer connection over the Peras certificate diffusion miniprotocol, which is enabled for all `InitiatorAndResponder` nodes. No keys, stake, or privileged access are needed. The attacker only needs to craft a CBOR-encoded `PerasCert` with a desired `pcCertRound` and `pcCertBoostedBlock` and send it over the wire. The stub is the only `validatePerasCert` implementation in the codebase and is unconditionally used in production.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real check before the Peras certificate diffusion miniprotocol is enabled in any environment where peers are not fully trusted. At minimum, the implementation must:

1. Verify the BLS aggregate signature in `pcSignature` against the claimed voter set in `pcVoters`.
2. Confirm that the voters in `pcVoters` are legitimate committee members for `pcRoundNo` using the epoch's VRF-based committee selection.
3. Confirm that the aggregate stake of `pcVoters` exceeds the quorum threshold.
4. Confirm that `pcBoostedBlock` refers to a block that exists and satisfies the `perasBlockMinSlots` age requirement.

Until this is implemented, the Peras certificate diffusion miniprotocol should be disabled or restricted to trusted peers only.

### Proof of Concept

1. Connect to a target node as a peer with the Peras certificate diffusion protocol enabled.
2. Send a `PerasCert` message with:
   - `pcCertRound` = any round not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the `RealPoint` of a block on a minority fork
3. Observe via tracing that `AddedPerasCertToDB` is logged and `ChainSelAddPerasCert` is enqueued.
4. If the minority fork's length plus 15 (the `perasWeight`) exceeds the current chain's length, observe the node switch to the minority fork.

The stub is at: [1](#0-0) 

The stub is wired into the production cert pool writer at: [2](#0-1) 

The network handler installs this writer for all inbound peer connections at: [3](#0-2) 

The `processCerts` function that unconditionally accepts all certs when validation always returns `Right`: [4](#0-3)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```
