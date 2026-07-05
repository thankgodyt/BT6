### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally accepts every inbound certificate without performing any cryptographic or quorum checks. Any unprivileged peer can craft a `PerasCert` for any block and any round, have it accepted by an honest node, and cause that block to receive an unearned Peras weight boost in chain selection — directly analogous to the external report's pattern where a validation step that should reject invalid inputs instead accepts them unconditionally, granting unearned value.

---

### Finding Description

The `BlockSupportsPeras` instance defined for all blocks at lines 320–389 of `SupportsPeras.hs` provides a stub `validatePerasCert` that returns `Right` for every certificate it receives:

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

No checks are performed on:
- The aggregate BLS signature over the election ID and boosted block hash
- Whether the claimed voters were actually eligible committee members
- Whether the quorum threshold was actually met
- VRF proofs for non-persistent voters

This stub is wired directly into the production certificate ingest path. In `PerasCert.hs`, `validatePerasCert mkPerasParams` is passed as the validation callback to `processCerts`, which is invoked when certificates arrive from peers via the Peras certificate diffusion miniprotocol:

```haskell
makePerasCertPoolWriterFromCertDB ... =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams)   -- stub: always Right
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    ...
    }
```

The same pattern appears in `makePerasCertPoolWriterFromChainDB`. The `processCerts` function partitions results with `partitionEithers`; since `validatePerasCert` never returns `Left`, every certificate passes and is stored.

Once stored, the certificate is used in chain selection via `weightBoostOfFragment` / `totalWeightOfFragment` in `Peras/Weight.hs`, which sums `PerasWeight` boosts for all boosted blocks on a fragment. The default `perasWeight` is 15, equivalent to 15 additional blocks of chain weight.

---

### Impact Explanation

An unprivileged peer can:

1. Craft a `PerasCert` with `pcCertRound` set to any round number and `pcCertBoostedBlock` pointing to any block on an adversarial fork.
2. Send it to an honest node via the Peras certificate diffusion miniprotocol.
3. The honest node calls `validatePerasCert`, which returns `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}` unconditionally.
4. The certificate is stored in `PerasCertDB` or `ChainDB`.
5. Chain selection via `wsvTotalWeight` / `totalWeightOfFragment` applies the 15-block weight boost to the adversarial block.
6. The adversarial chain gains a decisive weight advantage, causing honest nodes to prefer it over the honest chain.

This is a **critical bypass of Peras certificate validation** that enables unauthorized chain-selection manipulation by any connected peer, matching the allowed impact scope: *"Bypass of… Peras voting or certificate checks… that enables unauthorized… certificate acceptance."*

---

### Likelihood Explanation

The attack path is direct and requires no special privileges, stake, or cryptographic material. Any peer connected to the node can send crafted certificates via the Peras certificate diffusion miniprotocol. The stub is in production code (not test-only), and the TODO comment at line 350 explicitly acknowledges it is incomplete. The `processCerts` function in `PerasCert.hs` is the live ingest path used by both the `PerasCertDB` and `ChainDB` writers.

---

### Recommendation

Implement actual certificate validation in `validatePerasCert` before enabling Peras certificate diffusion in production. The validation must verify:

1. The aggregate BLS signature over the election ID and boosted block hash (using the concrete `PerasCert` in `Peras/Cert/V1.hs`).
2. Voter eligibility: each voter's seat index must correspond to a valid committee member (persistent or non-persistent) per the WFALS committee selection.
3. Quorum threshold satisfaction: the sum of vote weights of the included voters must exceed `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. VRF proofs for non-persistent voters via `localSortitionNumSeats`.

Until this is implemented, the Peras certificate diffusion miniprotocol must not be enabled on production nodes.

---

### Proof of Concept

```
Attacker (any peer) →
  sends PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlockHash }
  via Peras certificate miniprotocol

Honest node →
  processCerts ... (validatePerasCert mkPerasParams) ...
  validatePerasCert mkPerasParams cert
    = Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }
  → certificate stored in PerasCertDB / ChainDB
  → weightBoostOfPoint snap adversarialBlockPoint = PerasWeight 15
  → totalWeightOfFragment snap adversarialFrag = length + 15
  → chain selection prefers adversarial chain over honest chain
```

**Root cause** (analogous to the external report's rounding-to-zero): [1](#0-0) 

**Production ingest path wiring the stub**: [2](#0-1) 

**Chain selection weight application**: [3](#0-2)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
