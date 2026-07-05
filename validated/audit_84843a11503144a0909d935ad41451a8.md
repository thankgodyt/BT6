### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic verification of the aggregate BLS signature. An unprivileged peer can inject a completely forged Peras certificate via the cert-diffusion miniprotocol. When Peras is enabled, the forged certificate is accepted into the node's cert database and used to boost chain weight during chain selection, enabling an attacker to manipulate which chain the node considers canonical.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a received Peras certificate before it is stored and used for chain selection. The catch-all production instance (the only instance present in the codebase) implements this gate as a no-op stub:

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

This stub is the only `BlockSupportsPeras` instance in the repository; it applies to all block types via the `StandardHash blk` constraint:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

The cert-diffusion inbound handler is wired into the production node-to-node network stack unconditionally:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

The actual BLS aggregate-signature verification infrastructure exists and is correct in `PerasBLSCrypto`:

```haskell
verifyAggregateVoteSignature _ aggPk roundNo boostedBlock aggSig = do
  BLS.verifyWithRole @SIGN
    (unPerasBLSCryptoAggregateVoteVerificationKey aggPk)
    (hashVoteSignature roundNo boostedBlock)
    (unPerasBLSCryptoAggregateVoteSignature aggSig)
``` [4](#0-3) 

That verification is never called from `validatePerasCert`. The stub bypasses it entirely.

The analog to the external report is direct: just as the Primex referral contracts accepted signatures without chain-ID or expiration checks (allowing any signed message to be replayed), `validatePerasCert` accepts any certificate without checking the aggregate BLS signature at all — a strictly stronger form of the same vulnerability class (complete bypass rather than replay).

---

### Impact Explanation

When Peras is enabled, a `ValidatedPerasCert` returned by `validatePerasCert` is stored in the `PerasCertDB` and used to boost the weight of the certified chain fragment during chain selection:

```haskell
, getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
``` [5](#0-4) 

An attacker who injects a forged certificate for an adversarial chain fragment causes the honest node to assign that fragment a Peras weight boost it did not legitimately earn. This can flip chain selection toward a non-canonical or adversary-controlled chain, constituting a **chain-selection safety failure** triggered by an unprivileged peer over the cert-diffusion miniprotocol.

Impact class: **High** — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

- Peras is disabled by default (`"Note that if Peras is disabled (which is the default), there is no observable difference"`), which limits exposure on current mainnet.
- The cert-diffusion miniprotocol handler is compiled into and wired up in every production node build regardless of Peras status.
- Any private testnet, staging environment, or future mainnet deployment that enables Peras is immediately exposed.
- No privileged access is required; any connected peer can send a crafted `PerasCert` message.

Likelihood: **Medium** — not exploitable on mainnet today (Peras disabled), but exploitable in any Peras-enabled deployment without any further preconditions.

---

### Recommendation

Replace the stub with a real implementation that:

1. Deserializes the aggregate BLS vote-signing key from the committee membership data.
2. Calls `verifyAggregateVoteSignature` (already implemented in `PerasBLSCrypto`) against the certificate's aggregate signature, round number, and boosted block.
3. Verifies that the aggregate key was constructed from committee members whose combined stake meets the quorum threshold.
4. Returns `Left` with a descriptive `PerasValidationErr` on any failure.

Until the full committee-selection plumbing is available, the stub should at minimum return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the fail-safe direction is rejection rather than acceptance.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a Peras-enabled node as a normal peer.
2. Attacker sends a `PerasCert` message via the cert-diffusion miniprotocol containing an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to the attacker's preferred (non-canonical) chain tip.
3. The inbound handler calls `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on the received cert.
4. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` without inspecting the cert's aggregate BLS signature (there is no signature field in the stub's `PerasCert` data type and no verification call).
5. The `ValidatedPerasCert` is stored in the `PerasCertDB` and the Peras weight snapshot is updated.
6. Chain selection now treats the attacker's chain fragment as having a Peras boost, potentially causing the node to switch to the attacker's chain.

**Relevant code path:**

```
peer sends PerasCert
  → objectDiffusionInbound (NodeToNode.hs:375-384)
  → makePerasCertPoolWriterFromChainDB
  → validatePerasCert (SupportsPeras.hs:353-358)  ← always Right, no sig check
  → ChainDB.addPerasCertAsync
  → chain selection uses boosted weight
``` [1](#0-0) [3](#0-2)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L251-260)
```haskell
  verifyAggregateVoteSignature
    _
    aggPk
    roundNo
    boostedBlock
    aggSig = do
      BLS.verifyWithRole @SIGN
        (unPerasBLSCryptoAggregateVoteVerificationKey aggPk)
        (hashVoteSignature roundNo boostedBlock)
        (unPerasBLSCryptoAggregateVoteSignature aggSig)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```
