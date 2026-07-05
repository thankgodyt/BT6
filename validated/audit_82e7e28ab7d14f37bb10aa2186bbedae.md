### Title
Stub `validatePerasCert` Unconditionally Accepts All Peras Certificates, Enabling Chain Selection Manipulation via Crafted Network Input — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) without performing any actual certificate validation. An unprivileged peer connected via the Peras object diffusion protocol can send crafted certificates referencing arbitrary blocks already in the VolatileDB. These certificates bypass all validation, are added to the PerasCertDB, and trigger chain selection with artificial Peras weight boosts. This allows an adversary to manipulate chain selection and cause an honest node to prefer a non-canonical or adversarially-controlled chain.

---

### Finding Description

**Root cause** — `validatePerasCert` in the default `BlockSupportsPeras` instance is a stub that always succeeds:

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
``` [1](#0-0) 

This is the production instance used for all block types (`instance StandardHash blk => BlockSupportsPeras blk`), not a test-only stub. [2](#0-1) 

**Attacker-controlled entry path** — Peras certificates arrive from peers via the object diffusion protocol. The inbound processing function `processCerts` in `PerasCert.hs` calls `validatePerasCert` for each received certificate:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertInboundException errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never reached. Every crafted certificate passes and is forwarded to `addCert`.

**Chain selection trigger** — Once a certificate is added to the PerasCertDB, `chainSelSync` calls `chainSelectionForBlock` for the boosted block, using the artificial weight boost in chain comparison:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection then uses `weightedSelectView` / `WeightedSelectView` to compare fragments, where `wsvWeightBoost` from the fraudulent certificate inflates the total weight of the adversary's chain:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

**Exploit flow:**
1. Attacker connects to a target node via the Peras object diffusion protocol (no privileged access required).
2. Attacker identifies a block hash already present in the target's VolatileDB (observable via ChainSync headers).
3. Attacker crafts a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a competing fork.
4. `processCerts` calls `validatePerasCert` → always returns `Right` → certificate is accepted.
5. Certificate is added to PerasCertDB; `chainSelectionForBlock` is triggered.
6. Chain selection computes inflated `wsvTotalWeight` for the adversary's fork.
7. Node switches to the adversary's fork if the boosted weight exceeds the honest chain's weight.

---

### Impact Explanation

**High.** An unprivileged peer can manipulate Peras-weighted chain selection by injecting certificates with arbitrary boosts for any block in the VolatileDB. This can cause an honest node to abandon the canonical chain and adopt a non-canonical or adversarially-controlled fork, violating the chain selection security invariant. The `noPunishment` argument passed to `chainSelectionForBlock` for certificate-triggered selection means the peer is not even disconnected if the boosted block later fails full validation. [4](#0-3) 

---

### Likelihood Explanation

**Medium.** The Peras object diffusion protocol is active in the production node and accepts inbound certificates from any connected peer. The attacker only needs a standard peer connection and knowledge of a block hash in the target's VolatileDB (obtainable via ChainSync). No keys, stake, or operator access are required. The constraint is that the boosted block must already be present in the VolatileDB, which limits the attack window but does not prevent it.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- Committee membership of the certificate issuer for the given round.
- Cryptographic signature over the certificate fields.
- Round number is within the valid range relative to the current chain tip.
- The boosted block point is plausible (e.g., within the security parameter window).

Until a real implementation is available, consider gating the object diffusion protocol for Peras certificates behind a feature flag that is disabled by default, or rejecting all inbound certificates at the network boundary until validation is complete.

---

### Proof of Concept

1. Establish a peer connection to a target node via the Peras object diffusion mini-protocol.
2. Observe headers via ChainSync to identify a block hash `H` on a competing fork present in the target's VolatileDB.
3. Construct a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint S H }` for any round `R` not yet in the PerasCertDB.
4. Send the certificate batch to the target node.
5. `processCerts` invokes `validatePerasCert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. Certificate is stored; `chainSelectionForBlock` runs with the artificial boost applied to `H`'s chain.
7. If `PerasWeight (blockNo H) + boost > PerasWeight (blockNo currentTip)`, the node switches to the fork containing `H`.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-322)
```haskell
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
