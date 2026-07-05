### Title
Unconditional Certificate Acceptance in `validatePerasCert` Stub Bypasses All Peras Certificate Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or semantic validation. Any unprivileged peer can send a crafted `PerasCert` that will be accepted, stored in the `PerasCertDB`, and used to apply an unauthorized `perasWeight` boost to an arbitrary block, directly influencing chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for accepting Peras certificates received from peers. The default instance, which applies to all block types via `StandardHash blk`, is an explicit stub:

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

This stub is the live implementation used in the object diffusion inbound pipeline. In `processCerts`, the validation function passed is `validatePerasCert mkPerasParams`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls this function on every inbound certificate not already in the DB. Because the stub always returns `Right`, the `partitionEithers` check never produces any errors, and every certificate — regardless of content — is timestamped and forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

The accepted certificate is then stored in the `PerasCertDB` and triggers chain selection via `chainSelectionForBlock`:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The weight snapshot used during chain selection is built directly from the stored certificates, assigning `vpcCertBoost = perasWeight params` (currently `PerasWeight 15`) to the attacker-chosen block:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [5](#0-4) 

Chain selection then uses `wsvTotalWeight`, which adds `wsvBlockNo` and `wsvWeightBoost`, so the boosted chain gains 15 extra weight units over any unboosted competitor:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

The checks that are entirely skipped by the stub include: aggregate BLS signature verification, voter eligibility against the committee, quorum stake threshold, round number validity, and block age constraints (`perasBlockMinSlots`).

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash present in the node's VolatileDB as `pcCertBoostedBlock`. The node will accept it unconditionally, apply a `+15` weight boost to that block's chain, and potentially switch its preferred chain to one it would otherwise reject. This constitutes:

- **Bypass of Peras certificate/signature validation** enabling unauthorized certificate acceptance.
- **Chain selection manipulation**: the adversary can make an honest node prefer a non-canonical or adversarially-controlled chain by boosting a block on a minority fork, violating the Peras safety guarantee that only legitimately quorum-certified blocks receive boosts.

---

### Likelihood Explanation

The Peras object diffusion mini-protocol is wired into the live codebase and the inbound pipeline is active. Any peer that can establish a connection and speak the Peras cert diffusion protocol can exploit this. No stake, keys, or special privileges are required — only the ability to construct a `PerasCert` CBOR payload with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The one-cert-per-round deduplication in `PerasCertDB` means the attacker must use a fresh round number, but round numbers are a `Word64` and are not range-checked.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the eligible committee members listed in `pcVoters`.
2. Confirms each listed voter was a valid committee member for the given round (persistent seat via WFA or non-persistent seat via local sortition with a valid VRF proof).
3. Checks that the combined stake of the voters meets the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
4. Validates that `pcCertRound` is within the acceptable window and that the boosted block satisfies `perasBlockMinSlots`.

Until this is implemented, inbound Peras certificates from untrusted peers should be rejected entirely or the Peras cert diffusion mini-protocol should be disabled.

---

### Proof of Concept

On a private testnet with Peras cert diffusion enabled:

1. Observe a block `B` on a minority fork in the node's VolatileDB (slot `s`, hash `h`).
2. Construct a CBOR-encoded `PerasCert` with `pcCertRound = <any unused round>`, `pcCertBoostedBlock = (s, h)`, `pcVoters = <empty or arbitrary>`, `pcSignature = <zeroed>`.
3. Send this cert to the target node via the Peras cert object diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}`.
5. The cert is stored; `chainSelectionForBlock` is triggered for block `B`.
6. `wsvTotalWeight` for `B`'s chain increases by 15; if the honest chain's lead is ≤ 14 blocks, the node switches to the minority fork. [1](#0-0) [7](#0-6) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-127)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L209-213)
```haskell
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
