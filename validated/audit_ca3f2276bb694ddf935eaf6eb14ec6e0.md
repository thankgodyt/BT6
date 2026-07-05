### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain-Selection Weight Injection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used in production unconditionally returns `Right` from `validatePerasCert`, bypassing all cryptographic and quorum checks. An unprivileged peer can send a crafted `PerasCert` naming any block as the "boosted" target; the certificate is accepted without verification, stored in the `PerasCertDB`, and immediately triggers chain selection that applies Peras weight to the adversary-chosen block. This lets an unprivileged peer make an honest node prefer a non-canonical chain by injecting artificial weight boosts.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate's cryptographic proof, committee membership, and quorum before the certificate may influence chain selection. The production codebase ships a single catch-all instance (labeled "degenerate instance for all blks to get things to compile") that skips every check:

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

Every `PerasCert` value, regardless of content, is wrapped in `Right` and assigned the full `perasWeight` boost. There is no signature check, no committee-membership check, and no quorum check.

**Production call sites that use this stub:**

Both production pool-writer constructors pass this stub directly as the validation function:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [2](#0-1) [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` is the path wired into the production `NodeKernel` via `ObjectDiffusion`. [4](#0-3) 

**How `processCerts` uses the validation result:**

`processCerts` partitions the results of `validateCert` and rejects the whole batch only if any certificate returns `Left`. Since `validatePerasCert` always returns `Right`, every batch is accepted unconditionally:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [5](#0-4) 

**How an accepted certificate influences chain selection:**

Once stored, `chainSelSync` for `ChainSelAddPerasCert` reads the boosted block from the VolatileDB and calls `chainSelectionForBlock` with the updated `PerasWeightSnapshot`:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

`preferAnchoredCandidate` switches from simple length comparison to weighted comparison as soon as the `PerasWeightSnapshot` is non-empty:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- simple block-number comparison
  | otherwise =
      -- weighted comparison using the snapshot
``` [7](#0-6) 

A crafted certificate that names a block on an adversarial fork injects `perasWeight` into the snapshot for that block, potentially making the adversarial fork's total weight exceed the honest chain's total weight.

**Analog to the external report:**

The external report describes a "default value" (`address(0)`) that has special semantic meaning (self-delegation), where the absence of input validation allows that default to be set explicitly, corrupting state irreversibly. Here the analog is the "default" `validatePerasCert` implementation that maps every certificate to "valid", where the absence of real validation allows any peer-supplied certificate to corrupt the chain-selection weight state.

---

### Impact Explanation

An unprivileged peer can:
1. Diffuse a block on an adversarial fork so it lands in the target node's VolatileDB.
2. Send a crafted `PerasCert` naming that block as `pcCertBoostedBlock`.
3. The certificate bypasses all validation and is stored in the `PerasCertDB`.
4. Chain selection is re-run with the adversarial block now carrying `perasWeight` additional weight.
5. If the adversarial fork's weighted total exceeds the honest chain's total, the node switches to the adversarial fork.

This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended Peras security assumptions, violating the Common Prefix property.

---

### Likelihood Explanation

The `ObjectDiffusion` mini-protocol for Peras certificates is wired into the production `NodeKernel`. Any connected peer can send `PerasCert` messages. The only prerequisite is that the adversary's target block already exists in the node's VolatileDB, which is achievable by first diffusing the block normally. No keys, stake, or privileged access are required.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's cryptographic signature against the committee's aggregate key.
- That the signing committee members were legitimately elected for the claimed round.
- That the quorum threshold is met.

Until real validation is implemented, the production `processCerts` path should reject all inbound certificates (return `Left` unconditionally) rather than accept them unconditionally. The `-- TODO replace when actual plumbing is in place` comments at the two call sites in `PerasCert.hs` confirm this is a known gap; the fix must be in place before Peras is enabled on any network where adversarial peers are possible.

---

### Proof of Concept

1. Connect to a target node running this codebase with Peras enabled.
2. Diffuse a block `B` on a fork that is currently shorter than the honest chain; wait for it to appear in the node's VolatileDB.
3. Send a `PerasCert` message with `pcCertBoostedBlock = blockPoint B` and any `pcCertRound`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })`.
5. `addPerasCertAsync` enqueues the certificate; `chainSelSync` adds it to the `PerasCertDB` and calls `chainSelectionForBlock` for `B`.
6. `preferAnchoredCandidate` now uses the non-empty `PerasWeightSnapshot`; the fork containing `B` has total weight = `length(fork) + perasWeight`, which may exceed `length(honest chain)`.
7. The node switches to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
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
