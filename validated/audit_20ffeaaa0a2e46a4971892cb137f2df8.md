### Title
Unconditional `validatePerasCert` Stub with Hardcoded `mkPerasParams` Allows Any Peer to Inject Arbitrary Peras Certificates, Bypassing Chain-Selection Security — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The Peras certificate inbound pipeline in `processCerts` calls `validatePerasCert mkPerasParams` — a hardcoded default parameter set — instead of the actual node's configured `PerasCfg`. The `validatePerasCert` implementation itself is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic, round-number, or committee-membership check. Any unprivileged peer can therefore send a crafted `PerasCert` for an arbitrary round number boosting an arbitrary block; the certificate will pass "validation", be stored in the `PerasCertDB`, and trigger chain selection that awards the boosted block `perasWeight = 15` additional weight, potentially causing the honest node to switch to an adversarially chosen chain.

---

### Finding Description

**Root cause 1 — unconditional certificate acceptance.**

`validatePerasCert` is a degenerate stub:

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

Every certificate — regardless of its cryptographic proof, round number, or committee membership — is accepted and assigned a boost weight equal to `perasWeight params`.

**Root cause 2 — hardcoded default parameters instead of actual node config.**

Both pool-writer constructors pass the compile-time default `mkPerasParams` to `processCerts`:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [2](#0-1) [3](#0-2) 

`mkPerasParams` hard-codes `perasWeight = PerasWeight 15`, `perasQuorumStakeThreshold = 3/4`, and all other Peras parameters to fixed defaults regardless of what the running node is actually configured with. [4](#0-3) 

**Root cause 3 — the validated certificate directly drives chain selection.**

`processCerts` timestamps and stores every "validated" certificate, then `chainSelSync` triggers chain selection for the boosted block:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter ...
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [5](#0-4) 

Because `validateCert` always returns `Right`, the `(errs, _)` branch is never reached. The certificate is stored and `chainSelSync` is invoked:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

Chain selection then uses `weightedSelectView` / `preferAnchoredCandidate`, which adds the certificate's `vpcCertBoost` (always 15 from `mkPerasParams`) to the boosted block's chain weight: [7](#0-6) 

---

### Impact Explanation

This is a **Critical bypass of Peras certificate verification** that enables unauthorized certificate acceptance and chain-selection manipulation. An adversary controlling a single peer can:

1. Craft a `PerasCert` for any `PerasRoundNo` boosting any `Point blk` on a minority fork.
2. Send it via the object-diffusion mini-protocol.
3. The honest node accepts it unconditionally, stores it in `PerasCertDB`, and re-runs chain selection.
4. The minority fork gains `perasWeight = 15` additional weight, potentially exceeding the honest majority chain's weight and causing the node to switch to the adversarial fork.

This directly violates the Peras security guarantee that only a legitimately quorum-certified block should receive a boost. The attack requires no stake, no KES/VRF key, and no cryptographic material — only a network connection.

---

### Likelihood Explanation

The attack path is fully reachable from any peer connected via the Peras object-diffusion mini-protocol. No special privileges, keys, or stake are required. The only precondition is that Peras is enabled on the target node (currently opt-in, but the code path is production-ready and the feature is actively being integrated). The crafted certificate needs only a valid `PerasRoundNo` and a `Point blk` referencing a block already in the node's `VolatileDB` to trigger chain selection.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate committee signature, check that the round number is consistent with the current Peras round, and confirm committee membership and quorum.
2. **Thread the actual node `PerasCfg`** through to `processCerts` instead of the hardcoded `mkPerasParams`. Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` must accept the live configuration as a parameter.
3. **Add a round-number staleness check** in `processCerts`: reject certificates whose `PerasRoundNo` is outside the acceptable window relative to the current chain tip, analogous to the `PerasCertIgnoredTooOld` check already present in `chainSelSync`.

---

### Proof of Concept

The attack requires no code changes to the node. A peer sends a `PerasCert` message via the object-diffusion protocol:

```
PerasCert
  { pcCertRound      = <any round number>
  , pcCertBoostedBlock = <Point of a block on an adversarial fork in the VolatileDB>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams cert`, which unconditionally returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }
``` [8](#0-7) 

The certificate is stored in `PerasCertDB`. `chainSelSync` then calls `chainSelectionForBlock` for the boosted block. `preferAnchoredCandidate` computes `weightedSelectView` for both the current chain and the candidate, adding `PerasWeight 15` to the candidate's total weight:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [9](#0-8) 

If the adversarial fork's block number plus 15 exceeds the honest chain's block number, the node switches to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
