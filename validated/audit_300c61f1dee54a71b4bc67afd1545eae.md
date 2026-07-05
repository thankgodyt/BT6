### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` method unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. Because this stub is wired directly into the NTN Peras certificate diffusion inbound handler, any unprivileged remote peer can inject an arbitrary `PerasCert` for any block, causing it to be stored as a `ValidatedPerasCert` and triggering chain selection with an attacker-controlled boost weight. This is a complete bypass of Peras certificate authorization that mirrors the original report's "no access control on a privileged state-changing function."

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The sole `BlockSupportsPeras` instance, which covers all block types, implements `validatePerasCert` as an unconditional `Right`:

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

No signature check, no committee membership check, no quorum check, no round-number sanity check — every certificate is accepted. [1](#0-0) 

**Inbound path — NTN peer → `processCerts` → `addPerasCertAsync`:**

`makePerasCertPoolWriterFromChainDB` is the production writer used for all inbound NTN Peras certificate diffusion. It passes `validatePerasCert mkPerasParams` as the sole validation gate:

```haskell
(validatePerasCert mkPerasParams)
...
(void . ChainDB.addPerasCertAsync chainDB)
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, if all pass (which they always do), calls `addCert` — i.e., `ChainDB.addPerasCertAsync` — for each one: [3](#0-2) 

**NTN handler wiring — reachable from any remote peer:**

The NTN `mkHandlers` function wires `makePerasCertPoolWriterFromChainDB` directly into `hPerasCertDiffusionClient`, which is the inbound handler for every NTN connection:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**Chain selection impact:**

`addPerasCertAsync` enqueues the certificate for processing by the ChainDB background thread, which stores it in the `PerasCertDB` and triggers chain selection. The stored `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the Peras boost weight applied to the boosted block during chain selection via `getPerasWeightSnapshot`. An attacker-supplied certificate for any block therefore artificially inflates that block's chain selection weight. [5](#0-4) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain selection manipulation.**

Any unprivileged NTN peer can craft a `PerasCert` for an arbitrary `(roundNo, boostedBlock)` pair and have it accepted as a `ValidatedPerasCert` with full boost weight. Because Peras certificates directly influence chain selection (boosted blocks gain extra weight), an attacker can:

1. Inject a certificate boosting a minority-chain block, causing the victim node to prefer that chain over the honest majority chain.
2. Inject certificates for past rounds to retroactively alter the weight of already-stored blocks, potentially triggering a chain switch.
3. Inject certificates for future rounds to pre-position the node to switch chains when those blocks arrive.

This constitutes a bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance — matching the "Critical" scope item: *"Bypass of … certificate/vote verification bypass … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

**Likelihood: High.**

- The attack requires only a standard NTN connection, which any node on the network can establish.
- No keys, credentials, or privileged access are needed.
- The crafted certificate is a simple CBOR-encoded `(PerasRoundNo, Point blk)` pair — trivial to construct.
- The stub is the only `BlockSupportsPeras` instance in the codebase; there is no fallback or override.
- The NTN diffusion handler is active whenever the Peras feature flag is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion protocol is enabled in production. At minimum, the implementation must:

1. Verify the cryptographic aggregate signature over the certificate using the committee's BLS verification keys.
2. Confirm the certificate's round number is within the acceptable window relative to the current chain tip.
3. Confirm the boosted block is on the node's current chain (or a recent ancestor).
4. Confirm the certificate represents a genuine quorum of committee members for that round.

Until real validation is in place, the `hPerasCertDiffusionClient` handler should be disabled or gated behind a feature flag that is off by default in production builds, preventing any NTN peer from reaching `processCerts`.

---

### Proof of Concept

**Attacker preconditions:** A standard NTN connection to the victim node (no keys required).

**Steps:**

1. Connect to the victim node as a normal NTN peer.
2. Engage the `PerasCertDiffusion` mini-protocol (initiator side).
3. Send a crafted `PerasCert` message:
   ```
   PerasCert { pcCertRound = <target round>, pcCertBoostedBlock = <attacker-chosen block point> }
   ```
4. The victim node's `objectDiffusionInbound` handler calls `opwAddObjects [craftedCert]`.
5. `processCerts` calls `validatePerasCert mkPerasParams craftedCert`, which returns `Right (ValidatedPerasCert { vpcCert = craftedCert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
6. `ChainDB.addPerasCertAsync` enqueues the certificate; the background thread stores it in `PerasCertDB` and triggers chain selection.
7. Chain selection now applies the Peras boost weight to the attacker-chosen block, potentially switching the node's selected chain to a non-canonical fork.

**Expected outcome:** The victim node's chain selection is manipulated without any cryptographic authorization, causing it to prefer a chain chosen by the attacker.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L625-629)
```haskell
addPerasCertSync ::
  IOLike m =>
  ChainDB m blk -> WithArrivalTime (ValidatedPerasCert blk) -> m AddPerasCertChainSelOutcome
addPerasCertSync chainDB cert =
  waitPerasCertProcessed =<< addPerasCertAsync chainDB cert
```
