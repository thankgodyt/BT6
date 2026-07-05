### Title
Peras Certificate Validation Completely Bypassed — Any Peer Can Inject Arbitrary Weight Boosts into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (success) for every inbound certificate, skipping all cryptographic and protocol checks. Because accepted certificates are fed directly into the `PerasWeightSnapshot` used by `preferAnchoredCandidate` and `compareAnchoredFragments` during chain selection, an unprivileged peer can inject a crafted certificate that boosts an arbitrary block point, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Structural analog to the original report:**
The original bug has the pattern:
1. A state-update step runs (`update_fees_and_rewards` populates reward fields).
2. A required intermediate step is **missing** (`collect_rewards` to drain those fields).
3. A subsequent finalization check (`close_position` → `is_position_empty`) fails or produces wrong results because the intermediate step was skipped.

The analog here:
1. A certificate arrives from a peer and passes the deduplication check (`alreadyInDb`).
2. A required intermediate step is **missing**: actual cryptographic/protocol validation of the certificate (committee membership, VRF proof, round validity, quorum attestation).
3. The certificate is unconditionally accepted and its boost is applied to chain selection, producing an incorrect chain preference.

**Root cause — `validatePerasCert` stub:**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as a no-op that always succeeds:

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

This instance is declared as the catch-all for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

**Attacker-controlled entry path — `processCerts` in the production ObjectDiffusion writer:**

`makePerasCertPoolWriterFromChainDB` is the production handler for inbound Peras certificates received from peers. It passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

Inside `processCerts`, the validation result is the sole gate before acceptance:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validateCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer passes.

**How accepted certificates affect chain selection:**

Accepted certificates are stored in `PerasCertDB`. `implGetWeightSnapshot` converts them into a `PerasWeightSnapshot` keyed by `pcCertBoostedBlock`:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [5](#0-4) 

This snapshot is consumed by `preferAnchoredCandidate` and `compareAnchoredFragments` during every chain selection decision:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
        case preferCandidate
          (projectChainOrderConfig cfg)
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix) of
``` [6](#0-5) 

The `wsvTotalWeight` used for comparison is `BlockNo + weightBoost`. A crafted certificate with a large `perasWeight` can make a shorter, non-canonical fork appear heavier than the honest chain.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer sends a `PerasCert` with `pcCertBoostedBlock` pointing to any block on a minority fork. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and its boost is applied to `PerasWeightSnapshot`. During the next chain selection, `preferAnchoredCandidate` computes `wsvTotalWeight = BlockNo + injectedBoost` for the minority fork. If the injected boost exceeds the honest chain's block-number advantage, the node switches to the minority fork. This constitutes a chain selection safety failure driven entirely by a crafted network message from an unprivileged peer.

---

### Likelihood Explanation

**Medium.** The `makePerasCertPoolWriterFromChainDB` path is wired into the production `NodeKernel` ObjectDiffusion setup. The validation bypass is total — not partial — so no special timing or state is required. The only mitigating factor is that Peras is still under active development and may not yet be enabled on mainnet; however, the code is in production source files (not test stubs), and the TODO comments reference open issues rather than a feature flag that disables the path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with actual validation before the Peras ObjectDiffusion path is enabled in production. At minimum, the validation must check:
- Committee membership of the certificate issuer for the claimed round.
- Cryptographic signature / VRF proof over the certificate content.
- Round number is within the valid window relative to the current chain tip.
- The boosted block point exists on a known chain fragment.

Until real validation is implemented, the `makePerasCertPoolWriterFromChainDB` path should be gated behind an explicit feature flag that is disabled by default, so that the stub cannot be reached from the network.

---

### Proof of Concept

1. Connect to a node with Peras ObjectDiffusion enabled.
2. Send a batch containing one `PerasCert { pcCertRound = R, pcCertBoostedBlock = P }` where `P` is the tip of a minority fork with block number `N_fork` and the honest chain tip has block number `N_honest`.
3. Set `perasWeight` (via `mkPerasParams`) such that `N_fork + perasWeight > N_honest`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight }`.
5. The certificate is added to `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. `implGetWeightSnapshot` returns a `PerasWeightSnapshot` with `P ↦ perasWeight`.
7. On the next chain selection trigger, `preferAnchoredCandidate` computes `wsvTotalWeight` for the minority fork as `N_fork + perasWeight > N_honest + 0`, and `ShouldSwitch` is returned.
8. The node adopts the minority fork. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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
