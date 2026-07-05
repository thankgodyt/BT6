### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Unauthorized Chain-Selection Manipulation - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in `BlockSupportsPeras` is an acknowledged stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or semantic validation. Because the production inbound-certificate pipeline (`processCerts`) calls this function before adding certificates to the `PerasCertDB` and triggering chain selection, any unprivileged peer can inject arbitrary Peras certificates that boost any block of their choosing. Once a certificate is stored, the `PerasWeightSnapshot` becomes non-empty and `preferAnchoredCandidate` switches to the Peras weight-comparison path, potentially causing the honest node to prefer an adversarial fork over the canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` instance for all block types contains a placeholder implementation that always returns `Right`:

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

No quorum check, no BLS aggregate-signature verification, no committee-eligibility check, and no round-number sanity check is performed. Every `PerasCert` received from any peer is unconditionally promoted to a `ValidatedPerasCert`.

**Inbound pipeline — `processCerts`:**

The production inbound handler for Peras certificates received over the network calls `validatePerasCert mkPerasParams` as its sole gate before adding the certificate to the `ChainDB`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable and every certificate passes.

**Storage — `implAddCert` also carries the same TODO:**

The `PerasCertDB` implementation itself notes that non-trivial validation logic is still missing:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ...
``` [3](#0-2) 

**Chain-selection impact — `preferAnchoredCandidate` switches to Peras weight path:**

Once any certificate is stored, `isEmptyPerasWeightSnapshot` returns `False` and `preferAnchoredCandidate` compares chains using `weightedSelectView` instead of the plain block-number comparison:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights = ...  -- plain length comparison
  | otherwise =
      case AF.intersect ours cand of
        ...
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
``` [4](#0-3) 

An attacker who injects a certificate boosting a block on an adversarial fork adds `perasWeight params` to that fork's total weight. If the boost is large enough, the honest node switches to the adversarial fork.

**`chainSelSync` processes the injected certificate and triggers chain selection:**

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` that names any block hash as the boosted block. Because `validatePerasCert` always succeeds, the certificate is stored in `PerasCertDB`, the `PerasWeightSnapshot` becomes non-empty, and chain selection re-runs using Peras weights. If the attacker boosts a block on a competing fork, the honest node may switch to that fork, constituting a consensus safety failure: the node accepts a chain it would otherwise have rejected under the plain longest-chain rule. This is a direct bypass of Peras certificate/signature verification enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is wired into the production `NodeKernel` path via `processCerts` and `ChainDB.addPerasCertAsync`. Any peer that can connect to the node and send a `PerasCert` message can trigger this path. No stake, no key material, and no privileged access is required. The only prerequisite is that the boosted block must already be present in the node's `VolatileDB`; if it is not, the certificate is silently stored but chain selection is deferred until the block arrives.

---

### Recommendation

1. Implement real cryptographic and semantic validation inside `validatePerasCert` before the Peras certificate diffusion is enabled on any network. At minimum this must include: aggregate BLS signature verification over `(roundNo, boostedBlock)`, committee-eligibility proof verification for each voter, and quorum-threshold enforcement.
2. Until issue [#120](https://github.com/tweag/cardano-peras/issues/120) is resolved, gate the inbound certificate pipeline so that it rejects all certificates rather than accepting all of them (i.e., make the stub return `Left` unconditionally rather than `Right`).
3. Add an invariant check in `implAddCert` that refuses to store a certificate whose `ValidatedPerasCert` was produced by the stub path.

---

### Proof of Concept

1. Attacker connects to an honest node via the Peras object-diffusion mini-protocol.
2. Attacker observes that the node's `VolatileDB` contains block `B_adv` on a competing fork that is currently shorter than the canonical chain.
3. Attacker crafts `PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B_adv) }` with arbitrary (invalid) fields.
4. Attacker sends the certificate to the node. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
5. The certificate is added to `PerasCertDB`; `implGetWeightSnapshot` now returns a non-empty snapshot assigning `perasWeight params` to `point(B_adv)`.
6. `chainSelSync` triggers `chainSelectionForBlock` for `B_adv`. `preferAnchoredCandidate` now uses `weightedSelectView`, which adds the boost to the adversarial fork's total weight.
7. If `perasWeight params` exceeds the length difference between the canonical chain and the adversarial fork, the node switches to the adversarial fork — accepting a chain it would have rejected under the plain Praos longest-chain rule.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
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
```
