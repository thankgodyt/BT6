### Title
Unconditional `validatePerasCert` Acceptance Enables Permissionless Chain-Selection Griefing via First-Write-Wins Certificate Semantics — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole concrete implementation of `validatePerasCert` is a TODO placeholder that unconditionally accepts every certificate without performing any cryptographic or semantic check. The `PerasCertDB` enforces a strict "first-write-wins" rule: once a certificate for a given round is stored, any subsequent certificate for the same round is silently discarded on the assumption that "certificate equivocation is impossible." Because that assumption is violated by the missing validation, any unprivileged peer can race-submit a crafted certificate for the current round, permanently displacing the legitimate certificate and skewing chain selection toward an attacker-chosen block for that round.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op placeholder:**

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

This is the only instance of `BlockSupportsPeras` in the codebase (the degenerate catch-all `instance StandardHash blk => BlockSupportsPeras blk`). No BLS aggregate-signature check, no voter-eligibility check, no quorum check, and no round-number plausibility check is performed. Every certificate, regardless of content, is returned as `ValidatedPerasCert`.

**First-write-wins semantics in `PerasCertDB`:**

The `AddPerasCertPromise` documentation states:

> "If the PerasCertDB did already contain a certificate for this round, the certificate is ignored (as the two certificates must be identical because certificate equivocation is impossible)." [2](#0-1) 

The invariant "equivocation is impossible" is only sound when `validatePerasCert` actually validates. With the placeholder, equivocation is trivially possible: any peer can craft two structurally distinct certificates for the same round.

**Attacker-reachable entry path — cert diffusion protocol:**

The production node wires the Peras certificate inbound handler directly to `makePerasCertPoolWriterFromChainDB`, which calls `addPerasCertAsync` on the `ChainDB`:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [3](#0-2) 

`addPerasCertAsync` is the ChainDB entry point that triggers chain selection after storing the certificate:

```haskell
, addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [4](#0-3) 

**Exploit flow:**

1. Attacker connects to the target node as a normal peer.
2. Attacker observes the current Peras round number `R` (public information derivable from the slot number and `perasRoundLength`).
3. Attacker crafts a `PerasCert` with `pcCertRound = R` and `pcCertBoostedBlock = <hash of attacker-chosen block B'>`.
4. Attacker submits it via the cert diffusion protocol before the legitimate certificate for round `R` arrives.
5. The node calls `validatePerasCert`, which returns `Right` unconditionally.
6. The certificate is stored in `PerasCertDB`; the `PerasWeightSnapshot` is updated to give extra weight to chains containing `B'`.
7. When the legitimate certificate for round `R` arrives (boosting the honest block `B`), it is silently discarded as a "duplicate."
8. Chain selection permanently favours chains containing `B'` over chains containing `B` for the remainder of the round's influence window.

---

### Impact Explanation

Peras weight boosts are the mechanism by which the protocol achieves faster settlement: a certified block's chain receives additional weight in `preferAnchoredCandidate` comparisons. By injecting a fake certificate that boosts an attacker-chosen block, the adversary causes the honest node to permanently prefer a non-canonical chain for that round. This is a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions** — matching the High impact tier.

The `PerasWeightSnapshot` is consumed directly during chain selection:

```haskell
, getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
-- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
-- all blocks newer than the current immutable tip.
``` [5](#0-4) 

---

### Likelihood Explanation

The attack requires no stake, no cryptographic keys, and no privileged access. Any peer that can open a connection to the node can submit a certificate. The cert diffusion protocol is active in the production node setup. The only timing requirement is that the attacker's crafted certificate arrives before the legitimate one — a realistic race condition for a well-connected adversary or one co-located with the target.

---

### Recommendation

1. **Implement real validation in `validatePerasCert`** before the cert diffusion protocol is enabled in production. At minimum: verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the claimed voters' public keys, verify each voter's committee eligibility (persistent seat or VRF proof), and verify the quorum threshold is met.
2. **Disable the cert diffusion inbound handler** (`hPerasCertDiffusionClient`) until validation is complete, or gate it behind a feature flag that is off by default.
3. **Do not rely on "equivocation is impossible" as a DB invariant** until the validation layer enforces it cryptographically.

---

### Proof of Concept

```
Precondition: attacker is a connected peer; Peras is active; current round = R.

1. Compute target round R from current slot and perasRoundLength.
2. Choose any block hash H' (e.g., the genesis hash or a known stale block).
3. Construct PerasCert { pcCertRound = R, pcCertBoostedBlock = H' }.
4. Send it via the Peras cert diffusion mini-protocol.

Expected (buggy) outcome:
  - validatePerasCert returns Right unconditionally.
  - PerasCertDB stores the certificate; PerasWeightSnapshot updated for H'.
  - Legitimate certificate for round R (boosting honest block H) arrives later
    and is discarded: "certificate for this round already present."
  - Chain selection now weights chains containing H' more heavily than chains
    containing H, potentially causing a fork switch to a non-canonical chain.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L619-623)
```haskell
  -- includes switching to a different chain). If the PerasCertDB did already
  -- contain a certificate for this round, the certificate is ignored (as the
  -- two certificates must be identical because certificate equivocation is
  -- impossible).
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
