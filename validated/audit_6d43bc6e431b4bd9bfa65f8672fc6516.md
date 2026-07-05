### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right`, accepting every inbound certificate without any cryptographic or structural check. This stub is wired directly into the live node-to-node Peras cert diffusion miniprotocol handler. Any unprivileged peer can therefore inject an arbitrary `PerasCert` for any round and any block point; the certificate will be stored in the `PerasCertDB` and will trigger `chainSelectionForBlock` for the boosted block, potentially causing the honest node to switch to a non-canonical fork.

---

### Finding Description

**Root cause — stub validation always returns `Right`**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

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

No signature, quorum proof, round-number range, or committee-membership check is performed. Every certificate, regardless of content, is wrapped in `ValidatedPerasCert` and returned as valid.

**Production wiring — stub is used in the live NtN handler**

`makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

This writer is registered as the inbound handler for the Peras cert diffusion miniprotocol in the production node-to-node stack:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

**Chain selection side-effect**

`processCerts` calls `addCert` for every cert that passes `validateCert`. The `ChainDB.addPerasCertAsync` path feeds into `chainSelSync`, which calls `chainSelectionForBlock` for the boosted block if it is present in the `VolatileDB`:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that names any block hash present in the victim node's `VolatileDB` as the `pcCertBoostedBlock`. Because `validatePerasCert` never rejects, the certificate is stored and `chainSelectionForBlock` is invoked for that block. The Peras weight boost (`perasWeight = 15` in `mkPerasParams`) is added to the boosted block's chain weight, which can cause the node to prefer a fork it would otherwise not select. This is a **chain-selection manipulation** vulnerability: an adversary with no stake and no cryptographic keys can steer an honest node onto a non-canonical chain, violating the safety guarantees of the Peras protocol extension.

This matches the allowed impact: *"Bypass of... certificate/signature validation... that enables unauthorized... certificate acceptance"* and *"Chain selection... bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

The attack requires only a standard peer connection over the Peras cert diffusion miniprotocol, which is open to any node-to-node peer. No privileged keys, stake, or special access are needed. The attacker must know (or guess) a block hash present in the victim's `VolatileDB`, which is trivially obtainable by also running a chain-sync client against the same node. The attack is therefore fully reachable by any unprivileged network participant.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real check that verifies:
1. The certificate's round number is within the valid range relative to the current tip.
2. The certificate carries a valid quorum proof (aggregate signature or equivalent) over the claimed `pcCertBoostedBlock` and `pcCertRound`, verified against the committee selection data for that round.
3. The boosted block point is structurally valid (non-genesis, within the security parameter window).

Until real validation is implemented, inbound certificates from untrusted peers should be rejected at the miniprotocol boundary rather than accepted unconditionally. The existing `TODO` at issue `tweag/cardano-peras#120` should be treated as a security-critical blocker before the Peras diffusion miniprotocol is enabled on any production or pre-production network.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a victim node as a standard NtN peer.
2. Attacker sends a `PerasCert` message via the Peras cert diffusion miniprotocol with:
   - `pcCertRound` = any round number not already in the victim's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of a block on a minority fork present in the victim's `VolatileDB`
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15, ...}` unconditionally. [5](#0-4) 
5. The cert is added to the `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
6. `chainSelSync` retrieves the boosted block header from the `VolatileDB` and calls `chainSelectionForBlock`. [6](#0-5) 
7. The victim node's chain selection now treats the minority-fork block as having 15 additional weight units, potentially switching to the adversary-chosen fork.

**Expected outcome without the bug:** `validatePerasCert` should verify the quorum proof and reject the crafted certificate, leaving chain selection unaffected.

**Observed outcome with the bug:** The crafted certificate is accepted, the minority fork gains a Peras boost, and the node may switch chains.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-532)
```haskell
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
