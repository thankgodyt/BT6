### Title
Peras Certificate Signature Never Verified in Default `validatePerasCert` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default catch-all instance of `BlockSupportsPeras` implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate it receives, without verifying the aggregate BLS signature, the voter eligibility proofs, or the consistency between the claimed boosted block and the certificate payload. This is the direct analog of the external report's pattern: a commitment (the aggregate signature over `pcBoostedBlock` + `pcRoundNo`) is transmitted alongside the data it is supposed to commit to, but the commitment is never checked.

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate and vote handling. Its catch-all default instance covers every block type: [1](#0-0) 

The concrete `PerasCert` type carries four fields: the round number, the boosted block point, the voter set with eligibility proofs, and an aggregate BLS signature that is supposed to commit to the round and the boosted block: [2](#0-1) 

The default `validatePerasCert` implementation ignores all of those fields and unconditionally wraps the certificate in `Right`: [3](#0-2) 

The module-level comment in `V1.hs` itself acknowledges this gap: [4](#0-3) 

The same pattern applies to `validatePerasVote`, which also carries a TODO and performs no cryptographic check: [5](#0-4) 

### Impact Explanation

A Peras certificate, once accepted as `ValidatedPerasCert`, is used to assign a chain-weight boost (`vpcCertBoost = perasWeight params`) to the block named in `pcCertBoostedBlock`. Because `validatePerasCert` never verifies the aggregate BLS signature against the voter set or the boosted block, an unprivileged peer can craft a certificate that:

1. Names an arbitrary block as `pcCertBoostedBlock` (e.g., a block on a minority fork or an invalid block).
2. Carries a fabricated or zeroed `pcSignature`.
3. Claims any `pcVoters` set.

The node will accept this certificate, apply the full Peras weight to the attacker-chosen block, and may switch to a non-canonical chain — a direct bypass of Peras certificate/vote verification and a chain-selection integrity failure.

**Impact class:** Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.

### Likelihood Explanation

Peras vote and certificate objects are diffused over the peer-to-peer network. Any connected peer can submit a crafted certificate. No stake, key material, or privileged access is required. The only prerequisite is a network connection to a node running with Peras enabled. The stub is the active default for all block types until a proper override is registered, so the vulnerable path is exercised whenever `validatePerasCert` is called on an incoming certificate.

### Recommendation

Implement the actual BLS aggregate-signature verification inside `validatePerasCert` before any certificate is accepted as `ValidatedPerasCert`. Specifically:

1. Reconstruct the signed message from `pcRoundNo` and `pcBoostedBlock`.
2. Collect the public keys for every seat index listed in `pcVoters`, verifying each voter's eligibility proof (VRF output for non-persistent voters).
3. Verify `pcSignature` as a valid BLS aggregate signature over the reconstructed message under those public keys.
4. Reject the certificate (return `Left`) if any step fails.

The same applies to `validatePerasVote`: the VRF eligibility proof and the vote signature must be verified before the vote is counted toward quorum.

### Proof of Concept

A peer sends a `PerasCert` (serialized via `ToCBOR`) with:
- `pcRoundNo = <current round>`
- `pcBoostedBlock = <point of an attacker-chosen minority-fork block>`
- `pcVoters = <any non-empty voter bitmap>`
- `pcSignature = <zeroed/garbage BLS aggregate signature>`

The receiving node deserializes the certificate and calls `validatePerasCert`. The default implementation returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [6](#0-5) 

The certificate is now treated as fully validated. The Peras weight is applied to the attacker-chosen block, and chain selection may prefer the attacker's fork over the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L10-13)
```haskell
--
-- NOTE: the validation performed during serialization is minimal, and does not
-- cover any of additional semantic and cryptographic checks that must be
-- performed on the certificate later on.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```
