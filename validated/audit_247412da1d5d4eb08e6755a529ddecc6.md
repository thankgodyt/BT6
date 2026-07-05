### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Peras Weight Boost and Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Because the resulting `ValidatedPerasCert` is immediately stored in the `PerasCertDB` and its `vpcCertBoost` is folded into the `PerasWeightSnapshot` used by `preferAnchoredCandidate`, any unprivileged peer can inject a crafted certificate for an arbitrary block and cause the receiving node to apply a `PerasWeight 15` boost to that block during chain selection — potentially making a shorter, non-canonical chain appear heavier than the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase (the universal instance for all `StandardHash blk`). It never inspects the certificate's cryptographic proof, committee membership, round validity, or any other field. Every certificate, regardless of origin or content, is stamped `ValidatedPerasCert` with a boost of `perasWeight params`. [2](#0-1) 

**Inbound path — `processCerts`:**

`processCerts` in the object-diffusion pool writer calls `validateCert` (bound to `validatePerasCert mkPerasParams`) on every certificate received from a peer. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is forwarded to `addCert`. [3](#0-2) 

The production wiring in `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator and `ChainDB.addPerasCertAsync` as the sink: [4](#0-3) 

**Weight snapshot construction:**

`implGetWeightSnapshot` builds the `PerasWeightSnapshot` by iterating over every cert stored in `pcdsCertsByTicket` and calling `getPerasCertBoostedBlock`/`getPerasCertBoost` on each: [5](#0-4) 

**Chain selection consumption:**

`preferAnchoredCandidate` uses the `PerasWeightSnapshot` to compute `weightedSelectView` for each candidate fragment. The total weight is `blockNo + weightBoost`, so a fake cert for a block on a shorter adversary chain adds `PerasWeight 15` to that chain's score: [6](#0-5) [7](#0-6) 

The default `perasWeight` is `PerasWeight 15`: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` naming any block point as the boosted block. The receiving node accepts it without any validation, stores it, and applies a `+15` weight boost to that block in every subsequent chain selection comparison. With a single fake certificate, a chain that is 15 blocks shorter than the honest chain becomes equally preferred; with multiple fake certs targeting the same block (one per round, since deduplication is only by `PerasRoundNo`), the adversary can accumulate unbounded weight. This allows an unprivileged peer to cause the node to prefer a non-canonical, less-secure chain — a direct violation of the Peras chain-selection security property.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is wired into the production `ChainDB` path. Any peer that can establish a connection and speak the object-diffusion protocol can send arbitrary `PerasCert` objects. No stake, key material, or special privilege is required. The only rate-limiting factor is the per-round deduplication (`Set.member roundNo certIds`), which still allows one fake cert per round number — and there are `Word64`-many round numbers available.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's cryptographic proof (committee signature / VRF output).
2. That the claimed voters are legitimate committee members for the stated round.
3. That the aggregate stake of the signers meets the quorum threshold.
4. That the boosted block point is a known, valid block on a plausible chain.

Until the real implementation is in place, the object-diffusion inbound path for Peras certificates should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.

---

### Proof of Concept

1. Connect to a target node that has Peras object diffusion enabled.
2. Send a `PerasCert` message via the object-diffusion mini-protocol with:
   - `pcCertRound = PerasRoundNo <any unused round number>`
   - `pcCertBoostedBlock = <point of a block on the adversary's shorter chain>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always returns `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
4. The cert is stored in `PerasCertDB` via `ChainDB.addPerasCertAsync`.
5. `implGetWeightSnapshot` includes the fake cert in the `PerasWeightSnapshot`.
6. On the next chain selection event, `preferAnchoredCandidate` computes `wsvTotalWeight` for the adversary's chain as `blockNo + 15`, potentially exceeding the honest chain's `blockNo + 0`.
7. The node switches to the adversary's chain.

Repeat step 2 with a fresh `PerasRoundNo` to accumulate additional weight boosts beyond the initial 15.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
