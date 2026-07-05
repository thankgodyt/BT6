### Title
Degenerate `BlockSupportsPeras` Instance Unconditionally Accepts Any Peras Certificate Without Cryptographic Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` type class contains a universal degenerate instance explicitly added "to get things to compile" (the direct analog of the missing `usdxlConfig` declaration in the external report). This stub instance provides `validatePerasCert` as an unconditional `Right` — accepting every Peras certificate without any cryptographic check — and `validatePerasVote` without BLS signature verification. Any unprivileged peer that can submit a crafted Peras certificate or vote object reaches this stub and bypasses the intended validation gate entirely.

### Finding Description

At line 318–320 of `SupportsPeras.hs`, a universal overlapping instance is declared for all `StandardHash blk` types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

The `validatePerasCert` method body unconditionally returns `Right`, wrapping the caller-supplied certificate with the configured boost weight and performing zero cryptographic checks:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [2](#0-1) 

The `validatePerasVote` method only checks whether the voter's ID appears in the stake distribution map; it never verifies the BLS signature on the vote:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

The `forgePerasCert` method similarly always returns `Right` without validating that the supplied votes actually carry valid signatures or that quorum was legitimately reached: [4](#0-3) 

The `getPerasCertInBlock` method always returns `Nothing`, meaning no certificate embedded in a received block is ever extracted for validation: [5](#0-4) 

The `BlockSupportsPeras` class is the sole validation gate for Peras certificates and votes in the consensus layer. The BLS infrastructure for real validation exists in `Committee/Crypto/BLS.hs` (`verifyWithRole`, `linearizeAndVerifyVRFs`, `verifyProofOfPossession`) but is never called from the degenerate instance. [6](#0-5) 

### Impact Explanation

**Critical — Bypass of Peras certificate and vote validation.**

Because `validatePerasCert` always returns `Right`, any peer can submit an arbitrary `PerasCert` value (with any round number and any target block point) and have it accepted as a `ValidatedPerasCert` carrying the full configured `perasWeight` boost. Because `validatePerasVote` never checks the BLS signature, any peer that knows a valid voter's `PerasVoterId` (a public `KeyHash StakePool`, observable on-chain) can fabricate votes attributed to that voter. The resulting `ValidatedPerasCert` objects feed directly into Peras-aware chain selection, allowing an attacker to boost an arbitrary block's weight and cause honest nodes to prefer a non-canonical or adversarially-chosen chain.

### Likelihood Explanation

**High.** The degenerate instance is a universal instance covering every `StandardHash blk` — it is not gated behind a feature flag or a separate era. The TODO comment and the linked issue confirm the stub is intentional but unfinished. Any node running with Peras active that receives a crafted certificate or vote object over the Peras object-diffusion mini-protocol will exercise this path. No privileged access, key compromise, or stake majority is required; only knowledge of a legitimate voter's public `KeyHash` (publicly visible in the stake distribution) is needed to fabricate a passing vote.

### Recommendation

1. Remove or restrict the universal degenerate `instance StandardHash blk => BlockSupportsPeras blk` so it cannot silently override a correct era-specific instance.
2. Implement `validatePerasCert` to call `BLS.verifyWithRole` (or the appropriate aggregate verification path) against the certificate's embedded signature before returning `Right`.
3. Implement `validatePerasVote` to verify the BLS signature on the vote using `BLS.verifyWithRole` in addition to the stake-distribution membership check.
4. Implement `getPerasCertInBlock` to actually extract certificates from blocks so they are subject to validation.
5. Track completion against the referenced issue (`tweag/cardano-peras#73` and `#120`) before enabling Peras on any network.

### Proof of Concept

An unprivileged peer connected via the Peras object-diffusion mini-protocol constructs a `PerasCert` value with:
- `pcCertRound` set to the current Peras round
- `pcCertBoostedBlock` set to the point of any block the attacker wishes to boost (e.g., their own minority fork tip)

The peer submits this object. The receiving node calls `validatePerasCert params cert`. The degenerate instance returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally. The validated certificate is stored and used in chain selection, adding `perasWeight` to the attacker's chosen block. No BLS private key, no stake, and no quorum of real votes is required. [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L376-385)
```haskell
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L388-389)
```haskell
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L240-254)
```haskell
verifyWithRole ::
  forall r msg.
  ( SignableRepresentation msg
  , HasBLSContext r
  ) =>
  PublicKey r ->
  msg ->
  Signature r ->
  Either String ()
verifyWithRole pk msg (Signature sig) =
  verifyDSIGN
    (blsCtx (Proxy @r) (publicKeyScope pk))
    (unPublicKey pk)
    msg
    sig
```
