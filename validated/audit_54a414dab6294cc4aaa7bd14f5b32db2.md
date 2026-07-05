### Title
Unverified Proof-of-Possession Precondition in `aggregatePublicKeys` Enables Rogue Key Attack on Peras Certificate Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs`)

### Summary

`aggregatePublicKeys` in `BLS.hs` carries an explicit but unenforced precondition: *"this assumes that proofs of possession have already been verified for all keys in advance."* The Peras certificate verification path — `implVerifyCert` in both `WFALS.hs` and `EveryoneVotes.hs` — calls `aggregateVoteVerificationKeys` → `aggregatePublicKeys` without performing any Proof-of-Possession (PoP) check on the voter keys drawn from the stake distribution. This is the direct analog of the external report's pattern: code that assumes it holds a privilege (verified PoP) it does not actually possess. Without PoP enforcement, an unprivileged attacker who registers a crafted rogue BLS key on-chain can forge a Peras certificate that passes `verifyCert`, bypassing quorum and manipulating Peras-weighted chain selection.

### Finding Description

**Root cause — unverified precondition in `aggregatePublicKeys`:** [1](#0-0) 

The function calls `uncheckedAggregateVerKeysDSIGN` — the "unchecked" name confirms no PoP is performed inside. The precondition is a comment only; the type `PublicKey r` carries no proof that PoP was ever verified.

**Call chain — certificate verification never verifies PoP:**

`implVerifyCert` for `WFALS` collects voter public keys from the stake distribution and immediately passes them to `aggregateVoteVerificationKeys`: [2](#0-1) 

`aggregateVoteVerificationKeys` in `PerasBLSCrypto` calls `BLS.aggregatePublicKeys @SIGN` with no PoP step: [3](#0-2) 

The same pattern holds for `EveryoneVotes`: [4](#0-3) 

`verifyProofOfPossession` is defined in `BLS.hs` and exported, but is never invoked anywhere in the certificate verification path: [5](#0-4) 

**Rogue key attack mechanics:**

BLS aggregate signature schemes are vulnerable to a *rogue key attack* unless every participant proves possession of their private key before their public key is included in an aggregate. Without PoP, an adversary who observes the honest voters' keys `pk_1 … pk_n` can register a crafted key `pk_rogue = pk_target − (pk_1 + … + pk_n)` on-chain. The resulting aggregate key becomes `pk_target`, a key whose private key the adversary controls. The adversary can then produce a valid aggregate signature over any `(electionId, candidate)` pair, making `verifyAggregateVoteSignature` accept a certificate with no honest votes.

### Impact Explanation

A forged `WFALSCert` or `EveryoneVotesCert` that passes `verifyCert` is treated as a legitimate Peras quorum certificate. Peras certificates boost the weight of the chain they reference in chain selection: [6](#0-5) 

An attacker who can forge certificates can make an adversarial chain appear heavier than the honest chain, causing honest nodes to switch to a non-canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer with a registered stake pool can make honest nodes prefer a less-secure chain, violating the Peras safety guarantee without requiring a stake majority.

### Likelihood Explanation

The attacker's only on-chain requirement is registering a stake pool and submitting a crafted BLS `SIGN` public key as the pool's voting key — a normal, permissionless operation available to any ADA holder who can afford the pool deposit. The honest voters' keys are public (visible in the stake distribution). The crafted key can be computed offline before the epoch snapshot. No key compromise, admin access, or stake majority is needed.

### Recommendation

Enforce the precondition at the point of aggregation rather than relying on a comment. Two complementary fixes:

1. **At pool registration (ledger layer):** Require a valid `ProofOfPossession` for every BLS voting key submitted during pool registration, verified with `verifyProofOfPossession`. This is the standard defense and satisfies the precondition before any key enters the stake distribution.

2. **At certificate verification (consensus layer):** If PoP proofs are stored alongside pool keys in the stake distribution, re-verify them inside `implVerifyCert` before calling `aggregateVoteVerificationKeys`, or introduce a newtype wrapper (e.g., `PoP-verified PublicKey`) that can only be constructed after a successful `verifyProofOfPossession` call, making the precondition type-safe rather than comment-only.

### Proof of Concept

```
1. Observe the stake distribution for epoch E; collect all registered BLS SIGN
   public keys pk_1 … pk_n of pools expected to be in the voting committee.

2. Compute pk_rogue = pk_target - (pk_1 + … + pk_n) for a target key pk_target
   whose private key sk_target you control.

3. Register a new stake pool before the epoch-E snapshot with BLS SIGN key pk_rogue.
   No PoP is checked by the consensus layer.

4. In epoch E, construct a WFALSCert (or EveryoneVotesCert) listing seat indices
   for pools 1…n and your rogue pool, with aggSig = sign(sk_target, electionId || candidate).

5. Call verifyCert committee cert.
   - aggregateVoteVerificationKeys aggregates pk_1 + … + pk_n + pk_rogue = pk_target.
   - verifyAggregateVoteSignature verifies aggSig under pk_target → succeeds.
   - The forged certificate is accepted as a valid quorum certificate.

6. Attach this certificate to an adversarial chain; honest nodes applying Peras
   weight will prefer that chain over the canonical chain.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L274-287)
```haskell
verifyProofOfPossession ::
  PublicKey POP ->
  KeyHash StakePool ->
  ProofOfPossession ->
  Either String ()
verifyProofOfPossession pk stakePoolHash pop =
  verifyPossessionProofDSIGN
    extCtx
    (unPublicKey pk)
    (unProofOfPossession pop)
 where
  poolBytes = Hash.hashToBytes (unKeyHash stakePoolHash)
  baseCtx = blsCtx (Proxy @POP) (publicKeyScope pk)
  extCtx = baseCtx{blsSignContextAug = blsSignContextAug baseCtx <> Just poolBytes}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L291-313)
```haskell
-- | Aggregate multiple public keys into a single one.
--
-- PRECONDITION: all keys must have the same scope.
--
-- PRECONDITION: this assumes that proofs of possession have already been
-- verified for all keys in advance.
aggregatePublicKeys ::
  NE [PublicKey r] ->
  Either String (PublicKey r)
aggregatePublicKeys keys@(firstKey :| restKeys) = do
  -- Ensure all keys have the same scope before aggregation
  when (any (/= publicKeyScope firstKey) (fmap publicKeyScope restKeys)) $
    Left "Cannot aggregate public keys with different scopes"
  aggKey <-
    uncheckedAggregateVerKeysDSIGN
      . fmap unPublicKey
      . NonEmpty.toList
      $ keys
  pure $
    PublicKey
      { unPublicKey = aggKey
      , publicKeyScope = publicKeyScope firstKey
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L550-562)
```haskell
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L241-242)
```haskell
    aggPk <- BLS.aggregatePublicKeys @SIGN pks
    pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L325-337)
```haskell
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L1-5)
```haskell
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}
```
