### Title
Missing Proof-of-Possession Enforcement Before BLS Key Aggregation Enables Rogue-Key Forgery of Peras Certificates - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs`)

---

### Summary

`aggregatePublicKeys` in `BLS.hs` carries an explicit documented precondition that all BLS public keys must have had their Proof-of-Possession (PoP) verified before aggregation. However, neither `implVerifyCert` in `WFALS.hs` nor `implVerifyCert` in `EveryoneVotes.hs` — the two production certificate-verification paths — ever call `verifyProofOfPossession`. The precondition is stated but never enforced by any caller in the certificate-verification chain. This is the direct analog of M-14: a function declares a required condition at its interface, but the callers that invoke it never satisfy that condition, leaving the security guarantee hollow.

Without PoP enforcement, a stake pool that registers a crafted BLS public key can mount a classic rogue-key attack on the BLS aggregate, forging a Peras certificate that passes `verifyCert` without the required quorum of honest votes.

---

### Finding Description

**Root cause — the unenforced precondition**

`aggregatePublicKeys` in `BLS.hs` documents:

```
-- PRECONDITION: this assumes that proofs of possession have already been
-- verified for all keys in advance.
``` [1](#0-0) 

The function itself performs no PoP check; it unconditionally calls `uncheckedAggregateVerKeysDSIGN`: [2](#0-1) 

**Call chain — PoP is never verified**

`aggregatePublicKeys` is called by `aggregateVoteVerificationKeys` in `PerasBLSCrypto`: [3](#0-2) 

`aggregateVoteVerificationKeys` is called inside `implVerifyCert` for both `WFALS`: [4](#0-3) 

and `EveryoneVotes`: [5](#0-4) 

Neither `implVerifyCert` implementation calls `verifyProofOfPossession` at any point. The public keys are taken directly from the `ExtWFAStakeDistr` that was built by `mkExtWFAStakeDistr`: [6](#0-5) 

`mkExtWFAStakeDistr` accepts a `Map PoolId (LedgerStake, a)` where `a` is the public key payload — it performs no PoP verification. Neither does `mkWFALSVotingCommittee` nor `mkEveryoneVotesVotingCommittee`: [7](#0-6) 

`verifyProofOfPossession` exists in `BLS.hs` and is fully implemented: [8](#0-7) 

but it is never invoked anywhere in the production certificate-verification path.

**The rogue-key attack**

Without PoP, BLS key aggregation is vulnerable to the standard rogue-key attack. An attacker who controls a registered stake pool can submit a crafted BLS public key `pk_attacker = pk_target ⊖ (pk_1 ⊕ … ⊕ pk_n)` where `pk_1 … pk_n` are the honest voters' keys. When `implVerifyCert` aggregates all listed voters' keys (including `pk_attacker`), the result equals `pk_target`. The attacker signs the certificate payload with the private key corresponding to `pk_target` and submits a `WFALSCert` or `EveryoneVotesCert` listing themselves alongside honest voters. `verifyAggregateVoteSignature` succeeds because the aggregate key and aggregate signature are consistent — the honest voters never actually signed.

---

### Impact Explanation

A forged Peras certificate passes `verifyCert` and is accepted by the node as a valid quorum attestation. Peras certificates are used to boost blocks in chain selection; a forged certificate lets an attacker boost an arbitrary block without the required stake-weighted quorum of honest votes. This constitutes a **bypass of certificate verification** enabling unauthorized certificate acceptance, which falls squarely within the allowed High impact scope: "Bypass of leader eligibility, VRF/KES/certificate/signature validation… that enables unauthorized block, vote, or certificate acceptance."

---

### Likelihood Explanation

The attacker must be a registered stake pool and must be able to register a BLS public key without a valid PoP being checked by the ledger layer. If the Cardano ledger layer does not enforce PoP for Peras BLS key registration, the attack is directly reachable by any pool operator. The consensus layer provides no independent defense. The precondition is documented but structurally unenforced, making the gap persistent across all future callers of `aggregatePublicKeys` unless explicitly fixed.

---

### Recommendation

1. **Enforce PoP at committee construction time.** `mkExtWFAStakeDistr` (or the `VotingCommitteeInput` constructors) should accept and verify a `ProofOfPossession` alongside each `PublicKey`, calling `verifyProofOfPossession` for every key before it is stored in the `ExtWFAStakeDistr`. Keys that fail PoP verification must be rejected.

2. **Alternatively, enforce PoP inside `aggregatePublicKeys`.** Change the function signature to require a `[(PublicKey r, ProofOfPossession, KeyHash StakePool)]` and verify each PoP before aggregating, removing the unenforced precondition entirely.

3. **Add a type-level witness.** Introduce a `PoP`-verified newtype wrapper around `PublicKey` so that `aggregatePublicKeys` can only be called with keys that have passed PoP verification, making the precondition structurally enforced by the type system rather than a comment.

---

### Proof of Concept

```
Attacker setup:
  honest_keys = [pk_1, pk_2, pk_3]   -- registered pools with valid PoP
  target_key, target_sk = keygen()    -- attacker-controlled keypair
  rogue_key = target_key - pk_1 - pk_2 - pk_3  (BLS group subtraction)

Attacker registers stake pool with BLS key = rogue_key (no PoP check in consensus layer).

Attacker constructs WFALSCert:
  voters = {seat_1: pk_1, seat_2: pk_2, seat_3: pk_3, seat_attacker: rogue_key}
  agg_key = pk_1 + pk_2 + pk_3 + rogue_key = target_key
  agg_sig  = sign(target_sk, hash(electionId, candidate))

implVerifyCert:
  1. Traverses voters — all seat indices within bounds ✓
  2. aggregateVoteVerificationKeys → aggregatePublicKeys → agg_key = target_key ✓
  3. verifyAggregateVoteSignature(agg_key, electionId, candidate, agg_sig) → ✓

Certificate accepted. Honest voters pk_1, pk_2, pk_3 never signed.
```

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L293-296)
```haskell
-- PRECONDITION: all keys must have the same scope.
--
-- PRECONDITION: this assumes that proofs of possession have already been
-- verified for all keys in advance.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L297-313)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L240-242)
```haskell
  aggregateVoteVerificationKeys _ pks = do
    aggPk <- BLS.aggregatePublicKeys @SIGN pks
    pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L207-245)
```haskell
-- | Construct a 'WFALSVotingCommittee' for a given epoch
mkWFALSVotingCommittee ::
  VotingCommitteeInput crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (VotingCommittee crypto WFALS)
mkWFALSVotingCommittee
  ( WFALSVotingCommitteeInput
      nonce
      totalSeats
      stakeDistr
    ) = do
    ( numPersistentVoters
      , numNonPersistentVoters
      , persistentStake
      , nonPersistentStake
      ) <-
      bimap WFAError id $
        weightedFaitAccompliSplitSeats
          stakeDistr
          totalSeats

    let seats =
          Map.fromList
            [ (poolId, seatIndex)
            | (seatIndex, (poolId, _, _, _)) <-
                Array.assocs (unExtWFAStakeDistr stakeDistr)
            ]

    pure $
      WFALSVotingCommittee
        { extWFAStakeDistr = stakeDistr
        , candidateSeats = seats
        , persistentCommitteeSize = numPersistentVoters
        , nonPersistentCommitteeSize = numNonPersistentVoters
        , totalPersistentStake = persistentStake
        , totalNonPersistentStake = nonPersistentStake
        , epochNonce = nonce
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs (L365-378)
```haskell
mkExtWFAStakeDistr ::
  WFATiebreaker ->
  Map PoolId (LedgerStake, a) ->
  Either WFAError (ExtWFAStakeDistr a)
mkExtWFAStakeDistr tiebreaker pools
  | Map.null pools =
      Left
        EmptyStakeDistribution
  | otherwise =
      Right
        ExtWFAStakeDistr
          { unExtWFAStakeDistr = stakeDistrArray
          , numPoolsWithPositiveStake = numPoolsWithPositiveStakeAcc
          }
```
