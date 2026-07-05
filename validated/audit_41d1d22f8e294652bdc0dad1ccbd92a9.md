### Title
Unconditional Peras Certificate Acceptance Enables Unprivileged Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate validation function (`validatePerasCert`) is a stub that accepts every inbound certificate unconditionally. Because the cert-diffusion inbound handler is wired directly to this stub in the production node-to-node layer, any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary volatile block. The injected certificate is stored in `PerasCertDB`, updates the `PerasWeightSnapshot` used by chain selection, and triggers `chainSelectionForBlock` for the boosted block — potentially causing the honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub `validatePerasCert`:**

The `BlockSupportsPeras` type-class instance for all `StandardHash blk` (the only instance in the codebase) contains:

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

No signature verification, no committee-membership check, no round-number bounds check — every certificate is unconditionally accepted and assigned the full `perasWeight` boost. [1](#0-0) 

**Production wiring — cert diffusion inbound handler:**

In the node-to-node handler setup, the Peras cert diffusion inbound client is wired to `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on every received certificate:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [2](#0-1) 

**Chain-selection trigger on cert acceptance:**

Once a `ValidatedPerasCert` is accepted, `chainSelSync` stores it in `PerasCertDB` (updating the `PerasWeightSnapshot`) and immediately calls `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [3](#0-2) 

**Weight snapshot used in chain comparison:**

`PerasWeightSnapshot` is updated every time a new certificate is added (the `Fingerprint` changes), and it is consumed by `constructPreferableCandidates` / `chainSelection` via `preferAnchoredCandidate`:

```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
``` [4](#0-3) 

The `getWeightSnapshot` field of `PerasCertDB` is documented to update its fingerprint on every new certificate addition: [5](#0-4) 

---

### Impact Explanation

**Impact: High — chain-selection manipulation by an unprivileged peer.**

An attacker who connects as a peer can send a crafted `PerasCert` naming any block currently in the VolatileDB (block hashes are public; they are diffused to all peers). The stub `validatePerasCert` accepts it, the `PerasWeightSnapshot` is updated to include the full `perasWeight` boost for that block, and chain selection is re-run. If the fork containing the boosted block now has greater weight than the current selection, the honest node switches to it — accepting a non-canonical or adversarially-chosen chain without any cryptographic justification.

This matches the allowed impact: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Likelihood: Medium** (conditional on Peras cert diffusion being negotiated with peers).

- The inbound handler is registered unconditionally in the production node-to-node layer.
- No stake, no key material, and no special privilege is required — any connecting peer can send a `PerasCert` message.
- The only constraint is that the boosted block must be present in the VolatileDB, which is trivially satisfied since blocks are publicly diffused.
- The Peras protocol is under active development (multiple `TODO` markers referencing issue #120 and #73), so the stub may be live in testnet deployments even if not yet on mainnet.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert`: verify the aggregate signature against the claimed committee members, check committee eligibility using the stake distribution and committee-selection data, and enforce round-number bounds.
2. **Until real validation is in place**, gate the cert-diffusion inbound handler behind a feature flag that is disabled by default, or have `validatePerasCert` return `Left PerasValidationErr` unconditionally (mirroring the current behavior of `validatePerasVote` when the stake distribution is empty).
3. **Track the open issue** at `https://github.com/tweag/cardano-peras/issues/120` which already acknowledges the missing validation logic. [6](#0-5) 

---

### Proof of Concept

```
1. Attacker connects to victim node as a peer via the node-to-node protocol.

2. Attacker observes block hash H (slot S) currently in the victim's VolatileDB
   (e.g., a block on a competing fork, obtained via normal block diffusion).

3. Attacker crafts:
     cert = PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = (S, H) }

4. Attacker sends cert via the Peras cert-diffusion inbound mini-protocol.

5. Victim node calls:
     validatePerasCert params cert
   → returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
   (no signature check, no committee check)

6. Cert is stored in PerasCertDB; PerasWeightSnapshot is updated to add
   perasWeight to the chain containing H.

7. chainSelectionForBlock is called for H.
   preferAnchoredCandidate now sees the fork containing H as heavier.

8. If the fork's weight (including the injected boost) exceeds the current
   chain's weight, the victim node switches to the fork — accepting a
   non-canonical chain chosen by the attacker.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1132)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```
