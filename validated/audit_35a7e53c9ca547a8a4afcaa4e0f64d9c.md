### Title
Unenforced Proof-of-Possession Precondition in BLS Aggregate Vote Signature Verification Enables Rogue Key Attack on Peras Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs`)

---

### Summary

The `aggregatePublicKeys` function in `BLS.hs` carries an explicit documented precondition that Proof-of-Possession (PoP) must be verified for all keys before aggregation. However, neither `implVerifyCert` in `EveryoneVotes.hs` nor `implVerifyCert` in `WFALS.hs` calls `verifyProofOfPossession` before invoking `aggregateVoteVerificationKeys`. This unenforced precondition leaves the aggregate BLS signature verification path open to the classical rogue key attack, where an attacker registers a crafted BLS public key that cancels out a legitimate voter's key, enabling forgery of a Peras certificate without the victim voter's participation.

---

### Finding Description

**Root cause — unenforced precondition in `aggregatePublicKeys`:**

`aggregatePublicKeys` in `BLS.hs` explicitly documents:

```
-- PRECONDITION: this assumes that proofs of possession have already been
-- verified for all keys in advance.
aggregatePublicKeys ::
  NE [PublicKey r] ->
  Either String (PublicKey r)
aggregatePublicKeys keys@(firstKey :| restKeys) = do
  ...
  aggKey <- uncheckedAggregateVerKeysDSIGN ...
``` [1](#0-0) 

The function name `uncheckedAggregateVerKeysDSIGN` confirms no PoP check is performed inside the function itself.

**Certificate verification path — no PoP check before aggregation:**

In `EveryoneVotes.hs`, `implVerifyCert` collects voter verification keys from the ledger stake distribution and immediately aggregates them:

```haskell
(members, voteVerificationKeys) <-
  fmap munzip . flip traverse (NESet.toAscList voters) $ \case
    seatIndex
      | Just (_, voterPublicKey, voterStake, _) <-
          getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
          let voterVerificationKey =
                getVoteVerificationKey (Proxy @crypto) voterPublicKey
          ...
-- Verify aggregate signature
aggVerificationKey <-
  bimap CryptoError id $ do
    aggregateVoteVerificationKeys (Proxy @crypto) voteVerificationKeys
bimap InvalidCertSignature id $
  verifyAggregateVoteSignature (Proxy @crypto) aggVerificationKey electionId candidate aggSig
``` [2](#0-1) 

The same pattern appears in `WFALS.hs`: [3](#0-2) 

In neither path is `verifyProofOfPossession` called before `aggregateVoteVerificationKeys`.

**The vote signature digest does not include the voter's identity:**

`hashVoteSignature` in `PerasBLSCrypto` hashes only `roundNo || boostedBlockSlot || boostedBlockHash` — the voter's public key is absent from the signed message:

```haskell
hashVoteSignature roundNo boostedBlock =
  Hash.castHash . Hash.hashWith id . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes <> boostedBlockSlotBytes <> boostedBlockHashBytes
``` [4](#0-3) 

Because all voters sign the same message (election ID + candidate), the aggregate signature scheme relies entirely on the aggregate public key being sound. Without PoP, the aggregate key can be manipulated.

**Rogue key attack path:**

1. Attacker identifies a legitimate high-stake voter with BLS public key `pk_victim`.
2. Attacker computes `pk_rogue = pk_rogue_prime - pk_victim` (trivial elliptic curve arithmetic on BLS12-381 G1).
3. Attacker registers a pool with `pk_rogue` as their BLS vote verification key. Since PoP is not enforced in the certificate verification path, and the precondition in `aggregatePublicKeys` is only a comment, this key enters the stake distribution unchallenged.
4. A certificate is forged claiming both the attacker and the victim voted. `implVerifyCert` computes `aggPk = pk_victim + pk_rogue = pk_rogue_prime`.
5. The attacker signs the vote message with `sk_rogue_prime` to produce `aggSig`.
6. `verifyAggregateVoteSignature` calls `BLS.verifyWithRole @SIGN aggPk (hashVoteSignature roundNo boostedBlock) aggSig`, which passes because `aggSig` is a valid signature under `pk_rogue_prime`.
7. The certificate is accepted as valid even though the victim never voted. [5](#0-4) 

---

### Impact Explanation

A forged Peras certificate accepted by an honest node constitutes a **bypass of certificate signature validation**. Peras certificates boost specific blocks in chain selection; accepting a forged certificate can cause an honest node to prefer a block that did not legitimately receive quorum-level committee support. This falls under the allowed impact scope: *Bypass of certificate/signature validation that enables unauthorized certificate acceptance*, and *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain*.

---

### Likelihood Explanation

The rogue key attack on BLS aggregate signatures is a well-known, computationally trivial attack (pure elliptic curve arithmetic, no brute force required). The attacker only needs to register a pool with a crafted BLS key — a standard on-chain operation requiring no special privileges. The precondition in `aggregatePublicKeys` is documented but unenforced at the call sites in `implVerifyCert`. The `verifyProofOfPossession` function exists in `BLS.hs` but is not invoked in any production certificate verification path visible in the codebase.

---

### Recommendation

1. **Enforce PoP at certificate verification time**: In `implVerifyCert` (both `EveryoneVotes.hs` and `WFALS.hs`), call `BLS.verifyProofOfPossession` for each voter's BLS key before passing keys to `aggregateVoteVerificationKeys`. Alternatively, enforce PoP at the ledger level during pool BLS key registration so that only PoP-verified keys enter the stake distribution.

2. **Promote the precondition to a runtime check**: Convert the comment in `aggregatePublicKeys` into an enforced check, or rename the function to make the unchecked nature explicit and require callers to pass a proof that PoP was verified.

3. **Consider augmenting the vote message digest with the voter's public key**: Including the voter's serialized public key in `hashVoteSignature` would bind each individual vote signature to its issuer, providing defense-in-depth against cross-voter signature misattribution.

---

### Proof of Concept

```
-- Setup:
-- pk_victim = legitimate pool's BLS SIGN key (from stake distribution)
-- sk_rogue_prime = attacker's chosen private key
-- pk_rogue_prime = derivePublicKey sk_rogue_prime
-- pk_rogue = pk_rogue_prime - pk_victim  (BLS12-381 G1 point subtraction)

-- Attacker registers pool with pk_rogue as their BLS vote key.
-- Both attacker (seatIndex_A) and victim (seatIndex_V) appear in stake distribution.

-- Forged certificate:
-- voters = {seatIndex_A, seatIndex_V}
-- aggSig = signWithRole @SIGN sk_rogue_prime (hashVoteSignature roundNo boostedBlock)

-- During implVerifyCert:
-- voteVerificationKeys = [pk_victim, pk_rogue]
-- aggPk = aggregatePublicKeys [pk_victim, pk_rogue]
--       = pk_victim + (pk_rogue_prime - pk_victim)
--       = pk_rogue_prime
-- verifyWithRole @SIGN pk_rogue_prime (hashVoteSignature roundNo boostedBlock) aggSig
-- => Right ()   -- verification passes; victim never signed
``` [1](#0-0) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L88-115)
```haskell
hashVoteSignature ::
  ElectionId PerasBLSCrypto ->
  VoteCandidate PerasBLSCrypto ->
  Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
hashVoteSignature roundNo boostedBlock =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes
      <> boostedBlockSlotBytes
      <> boostedBlockHashBytes
 where
  roundNoBytes =
    BS.word64BE
      . unPerasRoundNo
      $ roundNo
  boostedBlockSlotBytes =
    BS.word64BE
      . unSlotNo
      . bytes32RealPointSlot
      . unPerasBoostedBlock
      $ boostedBlock
  boostedBlockHashBytes =
    BS.byteStringCopy
      . BS.fromShort
      . bytes32RealPointHash
      . unPerasBoostedBlock
      $ boostedBlock
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
