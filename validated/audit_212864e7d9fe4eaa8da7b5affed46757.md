### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every inbound certificate, regardless of its content. This is the direct structural analog to the external report's vulnerability: the "accept" branch is always taken and the "reject" branch (`Left PerasValidationErr`) is never triggered. Any unprivileged peer can send a crafted `PerasCert` that will be accepted, stored in the `PerasCertDB`, and used to artificially boost an arbitrary block in chain selection, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gating function for all inbound Peras certificates. The production instance at lines 350–358 of `SupportsPeras.hs` is a stub that performs zero validation:

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

This is the exact analog to the external report's vulnerability class: the accept path (`Right`) is unconditionally taken, and the reject path (`Left PerasValidationErr`) is structurally unreachable. The external report describes an indeterminate zone where neither accept nor reject fires; here the asymmetry is total — accept always fires.

The inbound certificate pipeline is:

**Step 1.** A peer sends a batch of `PerasCert` objects via the object diffusion mini-protocol. `processCerts` in `PerasCert.hs` (lines 164–185) calls `validateCert` — bound to `validatePerasCert mkPerasParams` — on each certificate not already in the DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _)            -> throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never reached. Every certificate passes.

**Step 2.** The validated certificate is added to the `PerasCertDB` via `ChainDB.addPerasCertAsync`. This is wired in both the `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` paths: [3](#0-2) 

**Step 3.** `chainSelSync` in `ChainSel.hs` (lines 483–531) processes the certificate. After a minimal age check on the boosted block's slot, it unconditionally triggers `chainSelectionForBlock` for the block named in the certificate:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Step 4.** Chain selection now uses `preferAnchoredCandidate`, which computes `wsvTotalWeight` as `blockNo + weightBoost`. The weight boost for a fragment is the sum of `vpcCertBoost` values for all boosted points on the fragment: [5](#0-4) 

Each accepted certificate contributes `perasWeight` (default: `PerasWeight 15`) to the targeted block's fragment weight. An attacker sending multiple crafted certificates for blocks on a competing fork can accumulate enough artificial weight to make that fork preferred.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` CBOR message (two fields: a `PerasRoundNo` and a `Point blk`) claiming to boost any block in the VolatileDB. Because `validatePerasCert` performs no cryptographic or semantic checks, the certificate is accepted, stored, and used to inflate the Peras weight of the targeted block. With `perasWeight = 15` per certificate and no limit on the number of certificates a peer can send (beyond the per-round deduplication by `pcCertRound`), an attacker can craft certificates for distinct round numbers to accumulate unbounded artificial weight on a minority fork. This constitutes a **chain selection safety failure**: an honest node is made to prefer a non-canonical or adversarially-controlled chain without any stake majority or key compromise.

---

### Likelihood Explanation

High. The attack requires only:
1. A network connection to the target node (any peer).
2. The ability to construct a valid CBOR-encoded `PerasCert` (two public fields: round number and block point hash — no cryptographic material needed).
3. Knowledge of a block hash in the target node's VolatileDB (obtainable via ChainSync).

No keys, no stake, no privileged access are required.

---

### Recommendation

Implement actual cryptographic and semantic validation inside `validatePerasCert` before the Peras certificate diffusion path is enabled in production. At minimum:

1. Verify the aggregate BLS signature (`pcSignature`) against the claimed voter set (`pcVoters`) and the message `(pcRoundNo, pcBoostedBlock)`.
2. Verify that each claimed voter was an eligible committee member for `pcRoundNo` using the committee selection data for that round.
3. Verify that the claimed voters collectively hold sufficient stake to satisfy the quorum threshold.
4. Verify that `pcCertRound` is within the valid acceptance window (not expired, not from the future).

Until this is implemented, the certificate diffusion mini-protocol must not be enabled on production nodes.

---

### Proof of Concept

```
1. Connect to a target node as a peer via the object diffusion mini-protocol.

2. Obtain a block hash H from the node's VolatileDB (e.g., via ChainSync headers).
   H is on a competing fork F that is currently lighter than the node's selection.

3. For each round R in {0, 1, 2, ..., N}:
   Craft a PerasCert CBOR message:
     { pcCertRound = R, pcCertBoostedBlock = BlockPoint(slot, H) }
   Send it to the node.

4. The node calls validatePerasCert mkPerasParams cert → Right (unconditionally).
   processCerts adds each cert to the DB.
   chainSelSync triggers chainSelectionForBlock for H on each cert.

5. After N certs, fork F has accumulated weight:
     blockNo(F) + N * perasWeight(15)
   Once this exceeds the weight of the honest chain, the node switches to F.
```

The deduplication in `processCerts` only skips certs whose `pcCertRound` is already in the DB. Using distinct round numbers for each crafted certificate bypasses this check entirely. [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-167)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
