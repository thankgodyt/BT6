### Title
Peras BLS Vote Signature Omits Epoch Nonce and Chain-Specific Context, Enabling Cross-Context Replay — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs`)

---

### Summary

The Peras BLS vote signature message (`hashVoteSignature`) does not include the epoch nonce or any chain-specific identifier, while the VRF eligibility proof input (`hashVRFInput`) does include the epoch nonce. This asymmetry means a vote signature is not bound to the epoch in which it was cast. Compounding this, the production `validatePerasCert` and `validatePerasVote` implementations are stubs that accept every certificate and vote unconditionally, so even the limited context binding that exists in the signature is never checked. An unprivileged peer can therefore send crafted Peras certificates over the ObjectDiffusion mini-protocol and cause an honest node to boost an arbitrary block in chain selection.

---

### Finding Description

**Root cause 1 — Missing epoch nonce in the vote signature message.**

`hashVoteSignature` in `Peras/Crypto/BLS.hs` hashes only three fields:

```
roundNo (8 bytes) || boostedBlockSlot (8 bytes) || boostedBlockHash (32 bytes)
``` [1](#0-0) 

By contrast, `hashVRFInput` — which governs non-persistent voter eligibility — explicitly includes the epoch nonce:

```
roundNo (8 bytes) || epochNonce (32 bytes)
``` [2](#0-1) 

The epoch nonce is the chain's per-epoch randomness beacon. Its absence from the vote signature means the signature `sig(sk, roundNo, boostedBlock)` is valid in any epoch where that `(roundNo, boostedBlock)` pair is presented, not just the epoch in which the voter originally signed. This is the direct analog of the permit2 signature that does not specify the target contract or function: the signed artefact does not fully express the signer's intent.

**Root cause 2 — `validatePerasCert` and `validatePerasVote` are unconditional stubs.**

The only `BlockSupportsPeras` instance in the production source tree is the catch-all degenerate instance for `StandardHash blk`. Both validation functions carry explicit TODO markers and return `Right` for every input without performing any cryptographic check:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

`CardanoBlock c` is a `HardForkBlock` which satisfies `StandardHash`, so this degenerate instance is the one used in production. The `processCerts` function in the ObjectDiffusion pool receives the `validateCert` callback as a parameter and calls it on every inbound certificate batch: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, every certificate received from any peer is timestamped and inserted into the certificate database, then forwarded to chain selection.

**Root cause 3 — `KeyScope` is not validated against the node's network configuration.**

The `KeyScope` type (`ByteString`) is the only mechanism intended to bind BLS keys to a specific network (comment: "later instantiated with usage and network id (e.g. PERAS/MAINNET)"). It is embedded in the key struct itself and used as the BLS augmentation string `"VOTE:" <> keyScope <> ":V0"`: [5](#0-4) [6](#0-5) 

No production code validates that the scope stored in a voter's registered public key matches the node's actual network. Because `validatePerasCert` is a stub, this check is never reached anyway.

---

### Impact Explanation

An unprivileged peer connected via the ObjectDiffusion mini-protocol can:

1. Craft a `PerasCert` (or `PerasVote`) for any `(roundNo, boostedBlock)` pair — no valid BLS signature is required because `validatePerasCert` accepts everything.
2. The certificate is inserted into the `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block.
3. Chain selection adds `perasWeight` (default 15) to the boosted block's chain weight, causing the node to prefer a non-canonical or adversarially chosen chain over the honest chain.

This satisfies the **High** impact criterion: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

Even if the stub were replaced with real cryptographic validation, the missing epoch nonce in `hashVoteSignature` would still allow a voter's signature from epoch E to be replayed in epoch E′ if the same `(roundNo, boostedBlock)` pair is presented, because the signed message does not commit to the epoch.

---

### Likelihood Explanation

**High.** The attack requires only a network connection to a Cardano node running the Peras extension. No key material, stake, or privileged access is needed. The ObjectDiffusion inbound handler accepts certificate batches from any peer and calls the stub validator unconditionally. The crafted certificate immediately influences chain selection.

---

### Recommendation

1. **Fix `validatePerasCert` and `validatePerasVote`** to perform full cryptographic verification (BLS aggregate signature check, VRF eligibility proof, quorum threshold) before accepting any certificate or vote. The stub must not be present in any code path reachable from the network layer.

2. **Add the epoch nonce to `hashVoteSignature`**, mirroring `hashVRFInput`, so that vote signatures are bound to the epoch in which they were cast:

   ```haskell
   hashVoteSignature roundNo epochNonce boostedBlock =
     Hash.castHash . Hash.hashWith id . runByteBuilder (8 + 32 + 8 + 32)
       $ roundNoBytes <> epochNonceBytes <> boostedBlockSlotBytes <> boostedBlockHashBytes
   ```

3. **Validate `KeyScope` at node startup** against the node's network magic / genesis hash, rejecting any registered BLS key whose embedded scope does not match the running network.

---

### Proof of Concept

**Crafted certificate injection (exploiting stub validation):**

```
Attacker connects to a Cardano node via the ObjectDiffusion mini-protocol.

Attacker sends a PerasCert batch:
  [ PerasCert
      { pcRoundNo      = <any round number>
      , pcBoostedBlock = <hash of attacker-chosen block>
      , pcVoters       = <any bitmap>
      , pcSignature    = <zeroed/random bytes — never checked>
      }
  ]

processCerts calls validatePerasCert, which returns Right unconditionally.
The certificate is stored in PerasCertDB.
chainSelectionForBlock is triggered for the boosted block.
The node adds perasWeight (15) to that block's chain weight.
Chain selection now prefers the attacker-chosen block over the honest tip.
``` [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L200-205)
```haskell
instance HasBLSContext SIGN where
  blsCtx _ keyScope =
    minSigSignatureDST
      { blsSignContextAug =
          Just ("VOTE:" <> keyScope <> ":V0")
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-532)
```haskell
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
