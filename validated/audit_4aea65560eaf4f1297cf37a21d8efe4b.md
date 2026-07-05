### Title
Missing Proof-of-Possession Verification Before BLS Key Aggregation Enables Rogue Key Attack on Peras Certificate Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs`)

### Summary

The `aggregatePublicKeys` function in the BLS committee crypto module carries an explicit, unenforced precondition that proofs of possession (PoPs) must be verified for all keys before aggregation. Neither `implVerifyCert` in `EveryoneVotes.hs` nor `implVerifyCert` in `WFALS.hs` calls `verifyProofOfPossession` before invoking `aggregateVoteVerificationKeys`. A registered stake pool that submits a maliciously crafted BLS public key (a rogue key) can exploit this gap to forge a valid-looking Peras certificate for any election ID and boosted-block candidate, causing honest nodes to accept an unauthorized certificate.

### Finding Description

**Root cause — unenforced precondition in `aggregatePublicKeys`:**

`aggregatePublicKeys` is documented with two preconditions:

```
-- PRECONDITION: all keys must have the same scope.
-- PRECONDITION: this assumes that proofs of possession have already been
--               verified for all keys in advance.
``` [1](#0-0) 

The second precondition is the standard BLS rogue-key-attack mitigation. Without it, an adversary can register a key `pk_malicious = g^sk_malicious − (pk_1 + … + pk_n)` so that the aggregate `pk_1 + … + pk_n + pk_malicious = g^sk_malicious`, a key for which the attacker alone knows the discrete log. The attacker can then produce a valid aggregate signature for any message using only `sk_malicious`.

**Vulnerable call sites — certificate verification never calls `verifyProofOfPossession`:**

In `EveryoneVotes.implVerifyCert`, the voter public keys are collected from the stake distribution and immediately passed to `aggregateVoteVerificationKeys` (which calls `aggregatePublicKeys`) with no PoP check:

```haskell
let voterVerificationKey = getVoteVerificationKey (Proxy @crypto) voterPublicKey
...
aggVerificationKey <- bimap CryptoError id $
    aggregateVoteVerificationKeys (Proxy @crypto) voteVerificationKeys
bimap InvalidCertSignature id $
    verifyAggregateVoteSignature (Proxy @crypto) aggVerificationKey electionId candidate aggSig
``` [2](#0-1) 

The identical pattern appears in `WFALS.implVerifyCert`: [3](#0-2) 

The `verifyProofOfPossession` function is defined and exported: [4](#0-3) 

but it is never invoked anywhere in the production certificate-verification path.

**Aggregate signature verification in `PerasBLSCrypto`** delegates directly to `BLS.aggregatePublicKeys` without any PoP step: [5](#0-4) 

### Impact Explanation

An attacker who registers a rogue BLS SIGN key in the on-chain stake distribution (a permissionless operation for any stake pool) can forge a Peras certificate for an arbitrary `(electionId, boostedBlock)` pair. A forged certificate accepted by honest nodes constitutes a **bypass of Peras voting and certificate checks**, allowing unauthorized boosting of any block — including an adversarially chosen one. This directly undermines the Peras chain-quality and settlement-speed guarantees and falls under the Critical impact category: bypass of Peras certificate/vote verification checks enabling unauthorized certificate acceptance.

### Likelihood Explanation

Registering a stake pool on Cardano is permissionless and requires only a small deposit. The rogue key construction (`pk_malicious = g^sk_malicious − Σ pk_i`) is standard BLS cryptography and requires only knowledge of the target voters' public keys, which are public on-chain data. No privileged access, leaked keys, or social engineering is required. The attack is deterministic and reproducible once the attacker's pool is included in the voter set of any election.

### Recommendation

Before calling `aggregateVoteVerificationKeys` (and thus `aggregatePublicKeys`) inside `implVerifyCert` for both `EveryoneVotes` and `WFALS`, verify the proof of possession for every voter's BLS SIGN key using `BLS.verifyProofOfPossession`. Alternatively, enforce PoP verification at the point where Peras BLS keys are admitted into the `ExtWFAStakeDistr` (i.e., during ledger-level key registration), and document that invariant so that `aggregatePublicKeys`'s precondition is provably satisfied before any call site reaches it. The existing `verifyProofOfPossession` primitive is already present and correct; it simply needs to be wired into the certificate-verification path.

### Proof of Concept

1. Attacker registers stake pool `P_adv` with BLS SIGN key `pk_adv = g^sk_adv − (pk_1 + pk_2 + … + pk_n)`, where `pk_1 … pk_n` are the known SIGN keys of all other eligible voters in a target election.
2. A Peras election occurs. The attacker constructs a `WFALSCert` (or `EveryoneVotesCert`) listing seat indices for `P_1 … P_n` and `P_adv`.
3. `implVerifyCert` computes `aggKey = pk_1 + … + pk_n + pk_adv = g^sk_adv`.
4. The attacker signs `hashVoteSignature(electionId, boostedBlock)` with `sk_adv` alone, producing `aggSig`.
5. `verifyAggregateVoteSignature` succeeds: `e(aggSig, g2) = e(hashVoteSignature(…), aggKey)` holds.
6. The forged certificate is accepted by every honest node, boosting the attacker's chosen block without any legitimate quorum of votes. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L289-313)
```haskell
-- * Aggregate keys and signatures

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L240-260)
```haskell
  aggregateVoteVerificationKeys _ pks = do
    aggPk <- BLS.aggregatePublicKeys @SIGN pks
    pure (PerasBLSCryptoAggregateVoteVerificationKey aggPk)

  aggregateVoteSignatures _ sigs = do
    aggSig <-
      BLS.aggregateSignatures @SIGN
        . fmap unPerasBLSCryptoVoteSignature
        $ sigs
    pure (PerasBLSCryptoAggregateVoteSignature aggSig)

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
