### Title
Missing Proof of Possession Verification for BLS Public Keys Enables Rogue Key Attack on Peras Certificate Verification - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs)

### Summary

The `aggregatePublicKeys` function in `BLS.hs` carries an explicit documented precondition that Proof of Possession (PoP) must be verified for all BLS public keys before aggregation. However, `verifyProofOfPossession` — the function provided for this purpose — is never called anywhere in production code. As a result, BLS public keys sourced from the ledger stake distribution are aggregated without PoP verification, leaving the aggregate signature scheme vulnerable to a rogue key attack. An attacker who registers a pool with a crafted BLS public key can manipulate the aggregate verification key so that a forged certificate passes `verifyAggregateVoteSignature`, enabling unauthorized Peras certificate acceptance.

### Finding Description

**Root cause — undischarged precondition in `aggregatePublicKeys`:** [1](#0-0) 

The comment at lines 293–296 states:

> `PRECONDITION: this assumes that proofs of possession have already been verified for all keys in advance.`

The function then calls `uncheckedAggregateVerKeysDSIGN` — the name itself signals that no possession check is performed inside. The precondition is never enforced by the caller.

**`verifyProofOfPossession` is defined but never called in production:** [2](#0-1) 

A `grep` across the entire repository confirms `verifyProofOfPossession` appears only inside `BLS.hs` itself (6 matches, all within the same file). No production call site exists.

**Certificate verification path that reaches `aggregatePublicKeys` without PoP:**

In `EveryoneVotes.implVerifyCert`, the voter public keys are read directly from the `ExtWFAStakeDistr` (which is populated from the ledger stake distribution) and passed to `aggregateVoteVerificationKeys`: [3](#0-2) 

`aggregateVoteVerificationKeys` in `PerasBLSCrypto` delegates directly to `BLS.aggregatePublicKeys @SIGN`: [4](#0-3) 

The same pattern holds in `WFALS.implVerifyCert`: [5](#0-4) 

**Why PoP matters for BLS_SIG:**

The signing context used is `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` (the basic scheme, not `BLS_POP`): [6](#0-5) 

The BLS_SIG basic scheme is explicitly vulnerable to rogue key attacks when PoP is not verified before key aggregation. The IETF BLS draft (referenced in the code comments) requires PoP verification as a prerequisite for safe key aggregation under BLS_SIG.

**Rogue key attack path:**

1. Attacker observes honest pool's registered BLS SIGN key `pk_h` (public on-chain).
2. Attacker generates a key pair `(sk_a, pk_a)`.
3. Attacker computes `pk_rogue = pk_a − pk_h` (BLS12-381 G2 group subtraction).
4. Attacker registers a pool with `pk_rogue` as their BLS key. No PoP is required because `verifyProofOfPossession` is never called.
5. When the consensus layer builds the aggregate verification key for a committee containing both pools: `agg = pk_h + pk_rogue = pk_h + pk_a − pk_h = pk_a`.
6. Attacker signs a forged certificate payload with `sk_a`.
7. `verifyAggregateVoteSignature` verifies the forged signature against `agg = pk_a` — it passes.

The forged certificate is accepted as if it had been co-signed by the honest pool.

### Impact Explanation

A successfully forged Peras certificate allows an attacker to make honest nodes accept a certificate attesting quorum for a block that did not actually receive it. Peras uses certificates to assign weight boosts to blocks during chain selection. Accepting a forged certificate causes nodes to prefer a non-canonical chain, breaking chain selection safety beyond the intended security assumptions. This maps to the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

### Likelihood Explanation

The attacker must register a pool (requires a pool deposit in ADA, a standard on-chain operation available to any participant) and must be selected into the same voting committee as the target honest pool. Committee membership is stake-weighted, so the attacker needs sufficient stake to be co-selected. This is a realistic capability for a moderately funded adversary. The honest pool's BLS key is public on-chain. The rogue key computation is deterministic and requires no brute force. Likelihood is **Medium**.

### Recommendation

1. Call `verifyProofOfPossession` for every BLS public key before it is admitted into the `ExtWFAStakeDistr` used to construct a `VotingCommittee`. This should occur at the point where pool BLS keys are ingested from the ledger state.
2. Alternatively, enforce the precondition inside `aggregatePublicKeys` itself by requiring callers to supply a proof of possession alongside each key, making the precondition structurally impossible to violate.
3. Add a comment to `aggregatePublicKeys` explicitly naming the call site responsible for discharging the precondition, so future refactors cannot silently drop the check.

### Proof of Concept

```
-- Attacker setup (off-chain):
let pk_h   = honest_pool_bls_sign_key   -- read from on-chain pool registration
let (sk_a, pk_a) = freshBLSKeyPair()
let pk_rogue = blsSubtract pk_a pk_h    -- BLS12-381 G2 group subtraction

-- Attacker registers a pool with pk_rogue as their BLS SIGN key.
-- No PoP is checked anywhere in the consensus layer (verifyProofOfPossession
-- is never called), so the registration succeeds.

-- At certificate verification time (consensus layer):
-- Committee contains honest pool (pk_h) and attacker pool (pk_rogue).
-- aggregatePublicKeys [pk_h, pk_rogue]
--   = uncheckedAggregateVerKeysDSIGN [pk_h, pk_rogue]
--   = pk_h + pk_rogue
--   = pk_h + (pk_a - pk_h)
--   = pk_a

-- Attacker forges a certificate signed with sk_a.
-- verifyAggregateVoteSignature aggKey electionId candidate forgedSig
--   verifies forgedSig against aggKey = pk_a  =>  PASSES
```

The forged certificate is accepted by `implVerifyCert` in both `EveryoneVotes` and `WFALS`, enabling unauthorized Peras certificate acceptance and consequent chain-selection manipulation.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L178-185)
```haskell
-- Basic over G1:
-- https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2.1-1
minSigSignatureDST :: BLS12381SignContext
minSigSignatureDST =
  BLS12381SignContext
    { blsSignContextDst = Just "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
    , blsSignContextAug = Nothing
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L273-287)
```haskell
-- | Verify a proof of possession signature for a public key
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L302-337)
```haskell
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L240-242)
```haskell
  aggregateVoteVerificationKeys _ pks = do
    aggPk <- BLS.aggregatePublicKeys @SIGN pks
    pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)
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
