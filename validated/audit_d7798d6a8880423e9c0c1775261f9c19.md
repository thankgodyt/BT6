### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Arbitrary Chain Weight Inflation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, bypassing all cryptographic and quorum verification. An unprivileged peer can send crafted `PerasCert` messages for N distinct rounds, each boosting any chosen block. Because `PerasWeightSnapshot` accumulates boosts from every accepted certificate, the attacker inflates the chain weight of a target block by N × `perasWeight`, causing honest nodes to prefer a non-canonical chain through the `WeightedSelectView` chain-selection rule.

---

### Finding Description

`validatePerasCert` in `BlockSupportsPeras.hs` is a degenerate stub that performs no verification:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

This stub is wired directly into the production certificate diffusion path in `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB`:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` calls this validator for every inbound certificate. Since it always returns `Right`, every certificate from every peer is accepted and stored in the `PerasCertDB` (deduplicated only by round number). [4](#0-3) 

The `PerasWeightSnapshot` is then built from all stored certificates, accumulating boosts for each certified block. [5](#0-4) 

Chain selection via `WeightedSelectView` uses `wsvTotalWeight`, which sums block number and `weightBoostOfFragment` from this snapshot. [6](#0-5) 

`weightBoostOfFragment` iterates every block in the fragment and sums their per-point boosts from the snapshot: [7](#0-6) 

`addToPerasWeightSnapshot` accumulates boosts for the same point using `Map.insertWith (<>)`, so N certificates for N distinct rounds each boosting the same block B produce a total boost of N × `perasWeight` for B: [8](#0-7) 

The glossary explicitly confirms this accumulation is the intended design: "the same point can be boosted multiple times." The attacker exploits the missing validation to inject fake boosts that were never legitimately earned.

---

### Impact Explanation

An unprivileged peer executes the following steps:

1. Sends N fake `PerasCert` messages, each with a distinct `pcCertRound` (e.g., rounds 1…N) and the same `pcCertBoostedBlock` pointing to target block B.
2. Each certificate passes `validatePerasCert` (always `Right`) and is stored in `PerasCertDB` — one per round, so the per-round deduplication check does not help.
3. `implGetWeightSnapshot` builds a `PerasWeightSnapshot` with N × `perasWeight` accumulated for block B.
4. `weightBoostOfFragment` returns N × `perasWeight` for any fragment containing B.
5. `preferCandidate` in `WeightedSelectView` switches to the heavier chain, causing the honest node to adopt a non-canonical chain containing B.

Additionally, `takeVolatileSuffix` uses `totalWeightOfFragment` to determine which blocks are volatile (subject to rollback). Inflating the weight of a block deep in the chain causes the node to treat more blocks as immutable (buried under weight ≥ k), potentially preventing legitimate rollbacks and corrupting the LedgerDB anchor. [9](#0-8) 

---

### Likelihood Explanation

The certificate diffusion mini-protocol is reachable from any unprivileged peer. No keys, stake, or special privileges are required. The attacker only needs to craft `PerasCert` CBOR messages with arbitrary `pcCertRound` and `pcCertBoostedBlock` fields. The stub is in production source files (`BlockSupportsPeras.hs`, `ObjectPool/PerasCert.hs`) and is actively wired into the cert diffusion path. N can be made arbitrarily large to overcome any honest chain's weight advantage.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over the certificate's election ID and candidate block against the combined verification keys of the claimed signers.
2. Checks that the signers form a valid quorum (total stake ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`) from the epoch's stake distribution.
3. Verifies each signer's seat index is within bounds in the `ExtWFAStakeDistr` and has positive stake.

Until the real implementation is in place, the cert diffusion path should reject all inbound certificates unconditionally (return `Left PerasValidationErr`) rather than accept them all.

---

### Proof of Concept

```haskell
-- Attacker constructs N fake certificates, each for a distinct round,
-- all boosting the same block B (e.g., the attacker's fork tip).
let fakeCerts =
      [ PerasCert
          { pcCertRound    = PerasRoundNo i
          , pcCertBoostedBlock = blockB   -- attacker's chosen block
          }
      | i <- [1 .. n]
      ]

-- processCerts calls (validatePerasCert mkPerasParams) for each cert.
-- validatePerasCert always returns Right, so all N certs are accepted.
-- PerasCertDB stores one cert per round (rounds 1..N).
-- PerasWeightSnapshot accumulates n * perasWeight for blockB.
-- weightBoostOfFragment returns n * perasWeight for any fragment containing blockB.
-- wsvTotalWeight of the attacker's chain = blockNo + n * perasWeight.
-- preferCandidate switches the honest node to the attacker's chain.
```

With `perasWeight = 15` (the default) and `n = 200`, the attacker adds 3000 units of artificial weight — enough to overcome a 3000-block honest chain advantage, far exceeding any realistic fork depth.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L259-267)
```haskell
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
