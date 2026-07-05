### Title
Stub `validatePerasCert` Accepts Any Certificate Without Voter or Quorum Validation, Enabling Unauthorized Chain Weight Boost — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance for all block types provides a stub `validatePerasCert` that unconditionally accepts every inbound Peras certificate without checking for a non-empty voter set or quorum. An unprivileged peer can send a certificate for any arbitrary block via the ObjectDiffusion mini-protocol; the certificate is stored in the `PerasCertDB` and applied as a Peras weight boost during chain selection, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` instance (the only instance that exists for all block types) provides a stub `validatePerasCert` that unconditionally returns `Right` for any certificate, regardless of content: [1](#0-0) 

The stub `PerasCert blk` data type has **no voter field at all**: [2](#0-1) 

This is the direct analog to the "empty listings" bug: just as `_createListing()` accepted `tokenIds = []` without validation, `validatePerasCert` accepts a certificate with zero voters (the only kind constructible with this type) without any quorum check, voter-set check, or signature verification.

The production inbound path in `processCerts` calls `validatePerasCert mkPerasParams` on every certificate received from a peer. Because validation always returns `Right`, every certificate is timestamped and stored in the `PerasCertDB`: [3](#0-2) 

Both production pool writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) use this stub validator: [4](#0-3) 

The concrete BLS-based certificate type (`Peras/Cert/V1.hs`) does enforce a non-empty voter bitmap during CBOR deserialization: [5](#0-4) 

However, this guard is irrelevant because the stub `PerasCert blk` type used by `validatePerasCert` is a completely different, voter-less type that bypasses the BLS deserialization path entirely. The stub is the only instance in the codebase and is explicitly wired into the production ObjectDiffusion writers.

---

### Impact Explanation

Certificates stored in the `PerasCertDB` are consumed by `getWeightSnapshot`, which feeds `weightBoostOfFragment` in `weightedSelectView`: [6](#0-5) 

The `wsvWeightBoost` field directly influences the `WeightedSelectView` comparison used for chain selection. A malicious peer can send a certificate for any `(round, block)` pair; the certificate is accepted, stored, and its weight boost is applied to the target block during chain selection. This lets an unprivileged peer cause an honest node to prefer a non-canonical or adversarially-chosen chain over the canonical one — a **High** chain-selection manipulation impact.

---

### Likelihood Explanation

**High.** Any peer reachable via the ObjectDiffusion mini-protocol can send arbitrary `PerasCert` values. No stake, keys, or special privileges are required. The validation function is a no-op stub (`Right` unconditionally), so exploitation requires only a network connection and knowledge of a target block hash and round number.

---

### Recommendation

Implement actual certificate validation in `validatePerasCert` that:

1. Rejects certificates whose voter set is empty (non-empty voter collection is a prerequisite for any valid quorum).
2. Verifies that the aggregate voting weight of the declared voters meets the configured quorum threshold (`stakeAboveThreshold`).
3. Verifies the aggregate BLS signature against the declared voter set and the `(round, block)` message.
4. Checks that the certificate's `pcCertRound` and `pcCertBoostedBlock` are consistent with the node's current chain state.

Until the full implementation is in place, the ObjectDiffusion cert writer should refuse to store any certificate rather than silently accepting all of them.

---

### Proof of Concept

1. Connect to a target node via the ObjectDiffusion mini-protocol (cert diffusion channel).
2. Craft a `PerasCert` with `pcCertRound = R` (any round) and `pcCertBoostedBlock = H` (hash of a non-canonical block the attacker wants boosted).
3. Send the certificate. `processCerts` filters out already-known rounds, then calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally — no voter check, no quorum check, no signature check.
5. The certificate is stored in `PerasCertDB` via `addCert . WithArrivalTime now`.
6. On the next chain-selection event, `getWeightSnapshot` returns a snapshot that includes a weight boost for block `H`.
7. `weightedSelectView` computes `wsvWeightBoost` using `weightBoostOfFragment`, elevating the fragment containing `H` above the canonical chain.
8. The node switches to the adversarially-chosen chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L165-166)
```haskell
    when (null voterSeatIndices) $
      throwError "Invalid Peras certificate: empty voters bitmap"
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L104-112)
```haskell
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
```
