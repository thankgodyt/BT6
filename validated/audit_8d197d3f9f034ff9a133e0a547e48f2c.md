### Title
Peras Vote Signature Hash Lacks Network-Instance Binding, Enabling Cross-Chain Replay of Votes and Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs`)

---

### Summary

The `hashVoteSignature` function that produces the message signed by every Peras BLS vote includes only the round number, the boosted block's slot, and the boosted block's hash. It contains no network magic, genesis hash, or any other chain-instance identifier. The `KeyScope` field that is documented as the intended domain-separator ("later instantiated with usage and network id, e.g. PERAS/MAINNET") is embedded in key material at deserialization time and is never validated against the running node's network configuration at vote or certificate verification time. As a result, a valid Peras vote or certificate produced on one network instance (e.g., mainnet) is cryptographically valid on any other instance that shares the same key scope string (e.g., a hard-fork chain), allowing an unprivileged peer to replay votes and certificates across chain instances.

---

### Finding Description

`hashVoteSignature` in `Ouroboros.Consensus.Peras.Crypto.BLS` constructs the message that every committee member signs:

```haskell
hashVoteSignature roundNo boostedBlock =
  Hash.castHash . Hash.hashWith id . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes <> boostedBlockSlotBytes <> boostedBlockHashBytes
```

The signed payload is exactly `roundNo ‖ slot ‖ blockHash` — 48 bytes with no network-specific field. [1](#0-0) 

The BLS layer does include a `KeyScope` in the augmentation context:

```haskell
instance HasBLSContext SIGN where
  blsCtx _ keyScope =
    minSigSignatureDST { blsSignContextAug = Just ("VOTE:" <> keyScope <> ":V0") }
``` [2](#0-1) 

However, the scope is a plain `ByteString` embedded in the key at deserialization time:

```haskell
-- | Key scope, later instantiated with usage and network id (e.g. PERAS/MAINNET)
type KeyScope = ByteString
``` [3](#0-2) 

`rawDeserialisePrivateKey scope bs` and `rawDeserialisePublicKey scope bs` accept whatever scope the caller supplies; there is no mechanism that derives or validates the scope from the node's `NetworkMagic` or genesis hash at verification time. [4](#0-3) 

`verifyVoteSignature` and `verifyAggregateVoteSignature` both call `BLS.verifyWithRole`, which reads the scope from the public key itself (`publicKeyScope pk`) — not from any network configuration passed in at call time:

```haskell
verifyWithRole pk msg (Signature sig) =
  verifyDSIGN (blsCtx (Proxy @r) (publicKeyScope pk)) (unPublicKey pk) msg sig
``` [5](#0-4) 

The concrete Peras vote-signing path confirms no network context is injected:

```haskell
signVote sk roundNo boostedBlock =
  PerasBLSCryptoVoteSignature . BLS.signWithRole @SIGN sk $ hashVoteSignature roundNo boostedBlock
``` [6](#0-5) 

The same gap applies to `hashVRFInput`, which hashes only `roundNo ‖ epochNonce` with no network identifier, so VRF eligibility proofs for non-persistent committee members are equally replayable across instances that share the same epoch nonce. [7](#0-6) 

Inbound certificates from peers are processed by `processCerts`, which calls `validatePerasCert` and, on success, stores the certificate in the `PerasCertDB` / `ChainDB`. There is no layer in this path that checks whether the certificate's embedded signatures were produced for the current network instance. [8](#0-7) 

---

### Impact Explanation

A Peras vote or certificate produced by a legitimate committee member on network A (e.g., mainnet) is byte-for-byte valid on network B (e.g., a hard-fork chain) as long as both networks load keys with the same `KeyScope` string. An adversary who collects votes or certificates from one chain and replays them on the other can cause a node on the target chain to accept a Peras certificate that was never legitimately quorum-reached on that chain. This constitutes a bypass of Peras certificate/vote verification, enabling unauthorized certificate acceptance and potentially forcing a node to treat a non-canonical block as boosted, corrupting chain selection.

---

### Likelihood Explanation

A hard fork is the most realistic trigger: both the pre-fork and post-fork chains share the same committee keys (same scope), the same round numbering restarts, and the same block hashes may collide in early slots. An attacker who participates in the pre-fork network can collect valid votes/certificates and replay them on the post-fork chain (or vice versa) without any special privilege beyond being a network peer. The attack requires no key compromise, no stake majority, and no operator action.

---

### Recommendation

1. **Short term:** Include the network's `NetworkMagic` (or genesis hash) in `hashVoteSignature` and `hashVRFInput`. Both functions already accept their full inputs as explicit arguments; adding a `NetworkMagic` parameter and encoding it as a fixed-width field in the byte builder is a minimal, non-breaking change.

2. **Medium term:** Derive `KeyScope` from the node's `NetworkMagic` at startup and pass it through to `rawDeserialisePrivateKey`/`rawDeserialisePublicKey`, then assert at `verifyVoteSignature` / `verifyAggregateVoteSignature` call sites that the key's scope matches the current network's scope. This closes the gap even if the message hash is not changed.

3. **Long term:** Document and test the full signature domain-separation scheme, analogous to the EIP-712 recommendation in the original report, to ensure all Peras signing contexts are unambiguously bound to a specific chain instance.

---

### Proof of Concept

**Private-testnet reproduction:**

1. Start two nodes on different network instances (different `NetworkMagic`) but with the same Peras committee keys loaded with the same `KeyScope` (e.g., `"PERAS/MAINNET"`).
2. On network A, allow a committee member to cast a vote for round `R` boosting block `B` (slot `S`, hash `H`). Capture the serialized `PerasVote` / `PerasCert`.
3. Submit the captured vote/certificate to a node on network B via the Peras object-diffusion mini-protocol.
4. `processCerts` on network B calls `validatePerasCert` → `implVerifyCert` → `verifyAggregateVoteSignature` → `BLS.verifyWithRole` → `hashVoteSignature(R, B)`. Because the hash contains no network identifier and the key scope matches, verification succeeds.
5. The certificate is stored in the `PerasCertDB` of network B and influences chain selection, despite never having been legitimately produced on network B.

The root cause is confirmed at: [1](#0-0) [3](#0-2) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L157-160)
```haskell
  signVote sk roundNo boostedBlock =
    PerasBLSCryptoVoteSignature
      . BLS.signWithRole @SIGN sk
      $ hashVoteSignature roundNo boostedBlock
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L83-84)
```haskell
-- | Key scope, later instantiated with usage and network id (e.g. PERAS/MAINNET)
type KeyScope = ByteString
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L94-104)
```haskell
rawDeserialisePrivateKey ::
  KeyScope ->
  ByteString ->
  Maybe (PrivateKey r)
rawDeserialisePrivateKey scope bs = do
  key <- rawDeserialiseSignKeyDSIGN bs
  pure $
    PrivateKey
      { unPrivateKey = key
      , privateKeyScope = scope
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L200-205)
```haskell
instance HasBLSContext SIGN where
  blsCtx _ keyScope =
    minSigSignatureDST
      { blsSignContextAug =
          Just ("VOTE:" <> keyScope <> ":V0")
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L249-254)
```haskell
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
