### Title
Peras Certificate Validation Unconditionally Returns Success Without Performing Any Checks — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) without performing any cryptographic or semantic validation on the certificate. Any crafted Peras certificate received from an unprivileged peer over the object-diffusion miniprotocol is accepted as valid, enabling unauthorized Peras certificate acceptance and fraudulent chain boosting.

---

### Finding Description

The vulnerability class from the external report is: **a validation/response function that fails to assign or evaluate a correctness indicator, causing invalid inputs to pass as valid (or vice versa)**. In the ChainLink case, the `success` field was never set to `true`, so valid oracle responses were treated as bad. The structural analog here is the inverse: the validation result is always set to `Right` (success) without ever evaluating whether the certificate is actually valid.

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides the following implementation:

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

No signature verification, no round-number bounds check, no boosted-block sanity check, and no quorum-membership check is performed. The function wraps any input certificate directly into a `ValidatedPerasCert` and returns `Right`.

This is the function invoked by the production inbound-certificate processing pipeline. In `processCerts` (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`), the caller-supplied `validateCert` callback is applied to every certificate received from a remote peer:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every inbound certificate is stored in the `PerasCertDB`.

---

### Impact Explanation

A Peras certificate carries a `vpcCertBoost` weight that is added to the chain-selection score of the boosted block. Once a fraudulent certificate is stored in the `PerasCertDB`, it participates in chain selection: the node may prefer a non-canonical or adversarially chosen chain because its tip appears to carry a Peras boost it did not legitimately earn. This is a **bypass of Peras certificate checks that enables unauthorized certificate acceptance**, matching the Critical impact tier: *"Bypass of … Peras voting or certificate checks … that enables unauthorized block, vote, or certificate acceptance."*

---

### Likelihood Explanation

The object-diffusion miniprotocol for Peras certificates is a public peer-to-peer channel. Any node that can establish a connection can send a batch of crafted `PerasCert` values. No stake, key material, or privileged access is required. The certificate wire format is documented (CBOR, 4-field list), so constructing a well-formed but semantically invalid certificate is straightforward.

---

### Recommendation

Replace the stub implementation with real validation. At minimum, `validatePerasCert` must:
1. Verify the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set.
2. Check that the claimed voters collectively hold stake above the quorum threshold.
3. Verify each voter's eligibility (persistent/non-persistent membership, VRF proof for non-persistent voters).
4. Validate that `pcCertRound` is within an acceptable range relative to the current tip.

Until a full implementation is available, the function should return `Left` (reject) rather than unconditionally accept, to fail safe.

---

### Proof of Concept

1. Connect to a target node via the Peras certificate object-diffusion miniprotocol.
2. Craft a `PerasCert blk` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block hash (e.g., a block on a minority fork).
3. Send the certificate in a batch to the target node.
4. `processCerts` calls `validateCert cert`, which resolves to `validatePerasCert params cert`.
5. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
6. The certificate is stored in the `PerasCertDB` with a full boost weight.
7. Chain selection now scores the adversarially chosen block higher than the honest tip, potentially causing the node to switch to a non-canonical chain.

**Root cause line:** [1](#0-0) 

**Inbound processing path that reaches the root cause:** [2](#0-1)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
