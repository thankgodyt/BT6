### Title
Missing Proof-of-Possession Enforcement Before BLS Key Aggregation Enables Rogue Key Attack on Peras Certificate Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs`)

---

### Summary

`aggregatePublicKeys` in `BLS.hs` carries an explicit unenforced precondition that proof-of-possession (PoP) has already been verified for every key before aggregation. The Peras certificate verification path (`implVerifyCert` → `aggregateVoteVerificationKeys` → `aggregatePublicKeys`) never calls `verifyProofOfPossession`, leaving BLS key aggregation open to a classic rogue key attack. An adversary who registers a crafted BLS public key in the stake distribution can forge a `WFALSCert` that passes `implVerifyCert` without holding the private keys of any honest committee member.

---

### Finding Description

`aggregatePublicKeys` in `BLS.hs` documents a critical security precondition:

```haskell
-- PRECONDITION: this assumes that proofs of possession have already been
-- verified for all keys in advance.
aggregatePublicKeys ::
  NE [PublicKey r] ->
  Either String (PublicKey r)
``` [1](#0-0) 

This precondition is **never enforced** in the production certificate verification path. The concrete `PerasBLSCrypto` instance calls `BLS.aggregatePublicKeys` directly with no PoP check:

```haskell
aggregateVoteVerificationKeys _ pks = do
  aggPk <- BLS.aggregatePublicKeys @SIGN pks
  pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)
``` [2](#0-1) 

This is called from `implVerifyCert` in `WFALS.hs`, which collects voter public keys from the stake distribution and immediately aggregates them:

```haskell
aggVerificationKey <-
  bimap CryptoError id $
    aggregateVoteVerificationKeys
      (Proxy @crypto)
      voteVerificationKeys
``` [3](#0-2) 

The `verifyProofOfPossession` function exists and is fully implemented:

```haskell
verifyProofOfPossession ::
  PublicKey POP ->
  KeyHash StakePool ->
  ProofOfPossession ->
  Either String ()
``` [4](#0-3) 

But it is never invoked anywhere in the `implVerifyCert` → `aggregateVoteVerificationKeys` → `aggregatePublicKeys` call chain. The `EveryoneVotes` committee implementation has the same gap: [5](#0-4) 

---

### Impact Explanation

Without PoP verification, BLS key aggregation is vulnerable to the **rogue key attack** (also called the "key cancellation attack"). An adversary registers a crafted public key `pk_adv` such that `pk_adv + pk_honest_1 + ... + pk_honest_n = pk_adv_controlled`, where `pk_adv_controlled` is a key whose private key the adversary knows. The adversary then:

1. Submits a `WFALSCert` listing their own seat plus the seats of honest committee members.
2. `implVerifyCert` collects the honest members' public keys from the stake distribution and aggregates them together with `pk_adv`.
3. The resulting aggregate key equals `pk_adv_controlled`, which the adversary can sign under.
4. `verifyAggregateVoteSignature` passes.

The adversary has forged a Peras certificate that appears to carry a quorum of honest committee member signatures, without knowing any honest member's private key. This is a **bypass of Peras voting certificate checks**, enabling unauthorized certificate acceptance for an attacker-chosen block candidate.

**Impact**: Critical — bypass of Peras certificate/vote verification, enabling unauthorized block boosting or chain selection manipulation.

---

### Likelihood Explanation

Any pool operator can register a BLS public key in the stake distribution. The rogue key construction requires only standard elliptic curve arithmetic on BLS12-381 G1 points, which is publicly documented and straightforward to implement. No privileged access, key compromise, or stake majority is required — only the ability to register a pool with a crafted BLS key, which is an unprivileged on-chain operation.

---

### Recommendation

Before calling `aggregatePublicKeys` (or `aggregateVoteVerificationKeys`) during certificate verification, verify the proof-of-possession for each voter's BLS public key. The `verifyProofOfPossession` function is already implemented and available. The PoP should be verified either:

1. **At key registration time** in the ledger, so that only PoP-validated keys ever enter the stake distribution; or
2. **At certificate verification time** in `implVerifyCert`, by requiring each voter entry in the `WFALSCert` to carry a `ProofOfPossession` and verifying it before aggregation.

Option 1 is preferred for performance, but Option 2 is a necessary defense-in-depth measure at the consensus layer.

---

### Proof of Concept

```
1. Attacker selects a target aggregate key T whose private key t they know.
2. Attacker observes honest committee members' registered BLS public keys:
     pk_1, pk_2, ..., pk_n  (from the stake distribution)
3. Attacker computes a rogue key:
     pk_adv = T - (pk_1 + pk_2 + ... + pk_n)   [BLS12-381 G2 point arithmetic]
4. Attacker registers a pool with pk_adv as their BLS SIGN key (no PoP required
   by the current code).
5. Attacker constructs a WFALSCert listing seat indices for themselves and
   honest members pk_1..pk_n, with an aggregate signature σ = Sign(t, msg).
6. implVerifyCert collects {pk_adv, pk_1, ..., pk_n} from extWFAStakeDistr,
   calls aggregateVoteVerificationKeys → BLS.aggregatePublicKeys (no PoP check),
   producing aggregate key = pk_adv + pk_1 + ... + pk_n = T.
7. verifyAggregateVoteSignature verifies σ under T → passes.
8. Node accepts the forged certificate as a valid Peras quorum decision.
``` [6](#0-5) [1](#0-0)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L240-242)
```haskell
  aggregateVoteVerificationKeys _ pks = do
    aggPk <- BLS.aggregatePublicKeys @SIGN pks
    pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L494-562)
```haskell
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
              let numSeats =
                    localSortitionNumSeats
                      (nonPersistentCommitteeSize committee)
                      (totalNonPersistentStake committee)
                      voterStake
                      (normalizeVRFOutput vrfOutput)
              case nonZero numSeats of
                Nothing ->
                  Left (ZeroNonPersistentSeats seatIndex)
                Just nonZeroNumSeats ->
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)

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
