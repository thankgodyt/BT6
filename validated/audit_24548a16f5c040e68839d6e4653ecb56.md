### Title
Missing Proof-of-Possession Enforcement Before BLS Key Aggregation Allows Certificate Signature Bypass - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs`)

---

### Summary

`aggregatePublicKeys` in `BLS.hs` carries an explicit but unenforced PRECONDITION that Proof-of-Possession (PoP) has been verified for every key before aggregation. Neither `implVerifyCert` in `EveryoneVotes.hs` nor in `WFALS.hs` calls `verifyProofOfPossession` before invoking `aggregateVoteVerificationKeys`. Additionally, unlike `linearizeAndVerifyVRFs` which explicitly guards against the BLS identity element (point at infinity), `aggregatePublicKeys` performs no such check. This is the direct structural analog of the `ecrecover`-returns-zero issue: a "null" cryptographic entity (the infinity point, the BLS identity element) can silently enter the aggregate key computation, weakening or bypassing certificate signature verification.

---

### Finding Description

`aggregatePublicKeys` is documented with two preconditions:

```
-- PRECONDITION: this assumes that proofs of possession have already been
-- verified for all keys in advance.
```

It calls `uncheckedAggregateVerKeysDSIGN` — the "unchecked" name explicitly signals that no PoP validation occurs inside the function. [1](#0-0) 

The concrete instantiation `aggregateVoteVerificationKeys` for `PerasBLSCrypto` directly delegates to `BLS.aggregatePublicKeys @SIGN` with no PoP check: [2](#0-1) 

In `implVerifyCert` for `EveryoneVotes`, the certificate verification path collects voter public keys from the stake distribution and immediately aggregates them — no `verifyProofOfPossession` call appears anywhere in this path: [3](#0-2) 

The same gap exists in `implVerifyCert` for `WFALS`: [4](#0-3) 

By contrast, `linearizeAndVerifyVRFs` — the batch VRF path — explicitly guards against the BLS identity element (point at infinity) on both the key and signature sides: [5](#0-4) 

`aggregatePublicKeys` has no equivalent guard. If the resulting aggregate key is at infinity (the BLS identity element), `verifyWithRole` is called with it, and the pairing-based check degenerates — any signature trivially satisfies the verification equation for the identity key.

---

### Impact Explanation

In BLS aggregate signature schemes, omitting PoP verification enables the **rogue key attack**: a pool operator registers a crafted voting key `pk_evil = pk_target - pk_honest` (group subtraction). When the verifier aggregates `pk_honest + pk_evil`, the result is `pk_target`, a key whose private key the attacker controls. The attacker can then produce a valid aggregate signature for any election candidate without cooperation from honest voters. This constitutes a **bypass of certificate/vote verification**, allowing unauthorized Peras certificate acceptance and enabling an unprivileged peer to make an honest node accept a certificate attesting a boosted block that was never legitimately voted for.

The impact maps to: *Bypass of certificate/vote verification that enables unauthorized certificate acceptance* — a Critical/High finding under the allowed scope.

---

### Likelihood Explanation

A pool operator is an unprivileged network participant in Cardano — pool registration is permissionless. Whether the Cardano ledger layer enforces PoP for BLS voting keys at registration time is outside this repository's scope. The consensus layer itself provides **no enforcement** of the precondition: `verifyProofOfPossession` is defined and exported but is never called in any production certificate verification path visible in this codebase. The asymmetry with `linearizeAndVerifyVRFs` (which does check infinity) suggests the infinity guard was added reactively for VRF paths but was not applied to the vote-key aggregation path. Likelihood is **Medium**: it requires a pool operator to register a crafted BLS key and for the ledger layer to not independently reject it.

---

### Recommendation

**Short term:** Add an explicit infinity-point guard inside `aggregatePublicKeys` mirroring the guard already present in `linearizeAndVerifyVRFs`:

```haskell
when (blsIsInf (unPublicKey aggKey)) $
  Left "Resulting aggregate key is at infinity"
```

**Short term:** In `implVerifyCert` for both `EveryoneVotes` and `WFALS`, call `verifyProofOfPossession` for each voter's public key before passing it to `aggregateVoteVerificationKeys`, or enforce the precondition at the point where keys enter the `ExtWFAStakeDistr`.

**Long term:** Promote the PoP precondition from a comment to a type-level or runtime invariant enforced at the boundary where public keys are admitted into the stake distribution, so that `aggregatePublicKeys` can never be called with unvalidated keys.

---

### Proof of Concept

1. Register two pools: honest pool H with key `pk_H`, and attacker pool A with crafted key `pk_A = pk_target - pk_H` (where `pk_target` is a key whose private key the attacker knows).
2. Both pools appear in the stake distribution with positive stake.
3. Attacker forges a certificate `WFALSCert` or `EveryoneVotesCert` listing seat indices for both H and A as voters.
4. `implVerifyCert` looks up `pk_H` and `pk_A` from the stake distribution, calls `aggregateVoteVerificationKeys`, which calls `BLS.aggregatePublicKeys @SIGN [pk_H, pk_A]`.
5. The aggregate key equals `pk_target`. The attacker signs the election candidate with the private key of `pk_target` and submits it as `aggSig`.
6. `verifyAggregateVoteSignature` succeeds — the certificate is accepted as valid despite honest pool H never having voted. [6](#0-5) [1](#0-0)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L410-414)
```haskell
  when (blsIsInf linearizedKeyPoint) $
    Left "Resulting key point is at infinity, cannot linearize"

  when (blsIsInf linearizedSigPoint) $
    Left "Resulting signature point is at infinity, cannot linearize"
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L240-242)
```haskell
  aggregateVoteVerificationKeys _ pks = do
    aggPk <- BLS.aggregatePublicKeys @SIGN pks
    pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
implVerifyCert committee = \case
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
