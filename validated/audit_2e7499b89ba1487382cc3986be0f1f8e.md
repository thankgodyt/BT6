### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance is a stub that always returns `Right`, bypassing all cryptographic and semantic certificate validation. Any unprivileged peer can send crafted `PerasCert` objects via the object diffusion mini-protocol. Each certificate passes validation unconditionally, is stored in the `PerasCertDB`, and triggers chain selection with the boosted weight applied. This allows an adversary to artificially inflate the Peras weight of any block on an adversarial fork and cause honest nodes to switch away from the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` provides a degenerate implementation for all block types. Its `validatePerasCert` method is explicitly marked as a TODO stub and unconditionally returns `Right`:

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

This stub is the implementation used in the production inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` — the production writer used when receiving certificates from peers — calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

Inside `processCerts`, the result of `validateCert` is partitioned. Because `validatePerasCert` always returns `Right`, the error list is always empty and every certificate is unconditionally added:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Once a certificate is stored, `chainSelSync` triggers chain selection for the boosted block. The selection logic calls `preferAnchoredCandidate` with the `PerasWeightSnapshot` derived from all stored certificates, including the injected ones:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection compares fragments using `preferAnchoredCandidate` with the real weight snapshot, where each boosted block contributes `perasWeight = PerasWeight 15` (the default) to the total weight of any chain containing it:

```haskell
preferAnchoredCandidate cfg weights ours cand
  ...
  | otherwise =
      case AF.intersect ours cand of
        ...
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
``` [5](#0-4) 

The total weight of a fragment is its block count plus the sum of all Peras boosts on that fragment:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

---

### Impact Explanation

This is a bypass of Peras certificate validation that enables unauthorized certificate acceptance. An adversary who is within 15 blocks of the honest tip (one boost weight) can inject a single fake certificate boosting a block on their fork and cause an honest node to switch to the adversarial chain. Multiple injected certificates compound the effect linearly. The attack does not require any privileged keys, stake majority, or VRF/KES compromise — only a peer connection and the ability to send a well-formed `PerasCert` message.

The impact matches the allowed scope: **bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain selection manipulation**, which is a consensus safety failure.

---

### Likelihood Explanation

Peras is disabled by default (`isEmptyPerasWeightSnapshot` short-circuits chain selection when no weights are present). The vulnerability is exploitable only when Peras is enabled. However, the stub is in production code, the object diffusion protocol is fully wired up, and the `makePerasCertPoolWriterFromChainDB` path is the designated production path for receiving peer certificates. Any peer connected to a Peras-enabled node can exploit this without any special privileges.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic and semantic validation before enabling Peras in production. At minimum, the implementation must verify:
1. The aggregate BLS signature over the round number and boosted block hash against the declared voter set.
2. That the declared voters were eligible committee members for the given round (committee selection check).
3. That the total stake of the declared voters meets the quorum threshold.

The concrete `PerasCert` type in `Peras/Cert/V1.hs` already carries the necessary fields (`pcSignature`, `pcVoters`) for this validation. [7](#0-6) 

---

### Proof of Concept

**Entry path** (no privileged access required):

1. Connect to a Peras-enabled node as an unprivileged peer via the object diffusion mini-protocol.
2. Send a `PerasCert` with `pcCertRound = R` and `pcCertBoostedBlock = <hash of adversarial block B>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
4. The certificate is stored in `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
5. `chainSelSync` fires `chainSelectionForBlock` for block `B`.
6. `preferAnchoredCandidate` computes the weight of the adversarial fragment including the injected boost of 15.
7. If the adversarial chain's block count plus 15 exceeds the honest chain's total weight, the node switches to the adversarial chain.

The `IgnorePerasCertTooOld` guard only rejects certificates whose boosted block slot is strictly less than the immutable tip slot — it does not validate the certificate's cryptographic content. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L487-492)
```haskell
  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```
