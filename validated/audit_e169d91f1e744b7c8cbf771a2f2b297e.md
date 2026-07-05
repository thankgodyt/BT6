### Title
Peras BLS Vote/VRF Signed-Message Payload Lacks Network-Identifier Domain Separation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs`)

---

### Summary

The Peras BLS voting and VRF eligibility scheme in `PerasBLSCrypto` omits any network or chain identifier from the signed-message payload. The only domain-separation mechanism is the `KeyScope` augmentation string embedded in the BLS signing context. However, `KeyScope` is never serialised as part of the key, is never validated against an expected network value during certificate or vote verification, and has no documented required value for any concrete network. This is a direct analog to the ChainPort finding: a signed artefact produced on one network can be replayed on another network that happens to use the same scope value.

---

### Finding Description

**`hashVoteSignature` and `hashVRFInput` contain no network identifier.**

`hashVoteSignature` hashes exactly three fields: `roundNo ‖ boostedBlockSlot ‖ boostedBlockHash`. [1](#0-0) 

`hashVRFInput` hashes `roundNo ‖ epochNonce`. [2](#0-1) 

Neither function includes a network magic, genesis hash, or any other chain-specific constant.

**The only domain separation is the `KeyScope` augmentation string, which is not part of the serialised key.**

`KeyScope` is a plain `ByteString` stored inside the `PrivateKey`/`PublicKey` wrapper. The comment explicitly notes it is "later instantiated with usage and network id (e.g. PERAS/MAINNET)". [3](#0-2) 

`rawSerialisePublicKey` serialises only the raw elliptic-curve point bytes — the scope is silently dropped. [4](#0-3) 

`rawDeserialisePublicKey` re-attaches a scope that is entirely caller-supplied; there is no way to verify it matches the scope used at signing time. [5](#0-4) 

**`verifyWithRole` trusts whatever scope is stored in the key it receives.**

```
verifyWithRole pk msg sig =
  verifyDSIGN (blsCtx (Proxy @r) (publicKeyScope pk)) (unPublicKey pk) msg sig
``` [6](#0-5) 

There is no step that asserts `publicKeyScope pk == expectedNetworkScope`. The same pattern is used in `verifyVoteSignature`, `verifyAggregateVoteSignature`, and `batchVerifyVRFOutputs`. [7](#0-6) [8](#0-7) 

**The augmentation string is the only thing that differs between roles, and it is also scope-dependent.**

```
instance HasBLSContext SIGN where
  blsCtx _ keyScope = minSigSignatureDST { blsSignContextAug = Just ("VOTE:" <> keyScope <> ":V0") }

instance HasBLSContext VRF where
  blsCtx _ keyScope = minSigSignatureDST { blsSignContextAug = Just ("VRF:"  <> keyScope <> ":V0") }
``` [9](#0-8) 

If two deployments (e.g., mainnet and a private testnet) both use the same scope value — including the degenerate case of an empty `ByteString` — the BLS augmentation strings are identical, and a vote or VRF output produced on one network is cryptographically valid on the other.

---

### Impact Explanation

Peras certificates carry a weight boost that directly influences chain selection. A node that accepts a replayed certificate from a different network (or from a different Peras deployment sharing the same scope) will assign an unearned weight boost to a block, potentially causing it to prefer a non-canonical chain. This falls squarely within the allowed impact class: *chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

The `processCerts` pipeline accepts inbound certificates from any peer over the miniprotocol, validates them with `validatePerasCert`, and stores them in `PerasCertDB` where they immediately influence the weight snapshot used by chain selection. [10](#0-9) 

---

### Likelihood Explanation

The precondition is that two deployments share the same `KeyScope` value. This is realistic in several scenarios:

1. **Scope not yet instantiated**: The comment "later instantiated with usage and network id" implies the scope is a placeholder. If the production wiring supplies an empty `ByteString` or a hardcoded constant that is reused across networks, the protection collapses entirely.
2. **Key reuse across environments**: Operators who reuse BLS committee keys between mainnet and a staging/testnet (a common operational mistake) would have the same raw key bytes; if the scope is also the same, replay is trivially possible.
3. **No enforcement at the verification call site**: Because `verifyWithRole` reads the scope from the key object rather than from a trusted configuration parameter, there is no compile-time or runtime guard that would catch a misconfigured scope.

---

### Recommendation

1. **Include a network identifier in the signed-message payload.** Extend `hashVoteSignature` and `hashVRFInput` to incorporate a chain-specific constant (e.g., the genesis hash or a network magic number) so that the signed bytes are unique per network regardless of the `KeyScope`.

2. **Serialise the `KeyScope` with the key.** `rawSerialisePublicKey` should include the scope bytes so that `rawDeserialisePublicKey` can recover and verify it rather than accepting a caller-supplied value.

3. **Validate the scope at the verification call site.** `verifyVoteSignature`, `verifyAggregateVoteSignature`, and `batchVerifyVRFOutputs` should accept an expected `KeyScope` from the node's trusted configuration and assert that `publicKeyScope pk == expectedScope` before calling `verifyWithRole`.

4. **Document the required scope value** for each network in the specification, analogous to how `ProtocolMagicId` is documented and enforced in the Byron DSIGN context. [11](#0-10) 

---

### Proof of Concept

```
-- Setup: two deployments both initialise keys with scope ""
let scope

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L121-136)
```haskell
hashVRFInput ::
  ElectionId PerasBLSCrypto ->
  Nonce ->
  Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
hashVRFInput roundNo epochNonce =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 32)
    $ roundNoBytes <> epochNonceBytes
 where
  roundNoBytes =
    BS.word64BE (unPerasRoundNo roundNo)
  epochNonceBytes =
    case epochNonce of
      NeutralNonce -> mempty
      Nonce h -> BS.byteStringCopy (Hash.hashToBytes h)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L162-170)
```haskell
  verifyVoteSignature
    pk
    roundNo
    boostedBlock
    (PerasBLSCryptoVoteSignature sig) =
      BLS.verifyWithRole @SIGN
        pk
        (hashVoteSignature roundNo boostedBlock)
        sig
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L83-91)
```haskell
-- | Key scope, later instantiated with usage and network id (e.g. PERAS/MAINNET)
type KeyScope = ByteString

-- | BLS private key type, parameterized by key role
type PrivateKey :: KeyRole -> Type
data PrivateKey r = PrivateKey
  { unPrivateKey :: !(SignKeyDSIGN BLS12381MinSigDSIGN)
  , privateKeyScope :: !KeyScope
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L135-145)
```haskell
rawDeserialisePublicKey ::
  KeyScope ->
  ByteString ->
  Maybe (PublicKey r)
rawDeserialisePublicKey scope bs = do
  key <- rawDeserialiseVerKeyDSIGN bs
  pure $
    PublicKey
      { unPublicKey = key
      , publicKeyScope = scope
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L147-151)
```haskell
rawSerialisePublicKey ::
  PublicKey r ->
  ByteString
rawSerialisePublicKey =
  rawSerialiseVerKeyDSIGN . unPublicKey
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L200-219)
```haskell
instance HasBLSContext SIGN where
  blsCtx _ keyScope =
    minSigSignatureDST
      { blsSignContextAug =
          Just ("VOTE:" <> keyScope <> ":V0")
      }

instance HasBLSContext VRF where
  blsCtx _ keyScope =
    minSigSignatureDST
      { blsSignContextAug =
          Just ("VRF:" <> keyScope <> ":V0")
      }

instance HasBLSContext POP where
  blsCtx _ keyScope =
    minSigPoPDST
      { blsSignContextAug =
          Just ("POP:" <> keyScope <> ":V0")
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L239-254)
```haskell
-- | Verify a  signature on a message with a  public key
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```
