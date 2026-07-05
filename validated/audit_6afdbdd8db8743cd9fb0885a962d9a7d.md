### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Returns `Right` for All Block Types — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The global `BlockSupportsPeras` instance, which applies to every block type via `instance StandardHash blk => BlockSupportsPeras blk`, implements `validatePerasCert` as a stub that unconditionally returns `Right` without performing any cryptographic or semantic checks. This stub is wired directly into the production Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can send any crafted `PerasCert` object over the network; it will pass "validation" and be stored in the `PerasCertDB`, where its boost weight is used in chain selection via `preferAnchoredCandidate`.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

The global instance is explicitly marked as a temporary shim ("TODO: degenerate instance for all blks to get things to compile") but is wired into production code. The `PerasCert` data type defined in this instance carries no cryptographic fields — only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`. There is nothing to verify even if validation were attempted. `validatePerasCert` always returns `Right ValidatedPerasCert{...}` regardless of the certificate's content.

**Production ingest path — `processCerts` and `makePerasCertPoolWriterFromChainDB`:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validation function to `processCerts`. This is the production writer used when Peras certificate diffusion is active. [3](#0-2) 

`processCerts` calls `validateCert` on each inbound certificate. Because `validatePerasCert` always returns `Right`, every certificate from every peer passes, is timestamped, and is stored in the `PerasCertDB` via `addCert`.

**Chain selection impact — `PerasCertDB.getWeightSnapshot` feeds `preferAnchoredCandidate`:** [4](#0-3) 

`implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certificates, mapping each `pcCertBoostedBlock` to its boost weight. This snapshot is consumed by `preferAnchoredCandidate`: [5](#0-4) 

When `isEmptyPerasWeightSnapshot weights` is false (i.e., when at least one certificate has been stored), chain selection switches to the Peras weighted path, comparing `weightedSelectView` of suffixes. A crafted certificate boosting an attacker-controlled block can make that block's chain appear heavier than the honest chain.

**The `PerasCertDB.implAddCert` has a TODO confirming the missing validation:** [6](#0-5) 

---

### Impact Explanation

**Classification: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

An attacker who can connect to a node with Peras certificate diffusion active can inject arbitrary `PerasCert` objects. Each accepted certificate contributes `perasWeight params` boost to the `pcCertBoostedBlock` point. By crafting a certificate that boosts a block on an attacker-controlled fork, the attacker can cause the node's `preferAnchoredCandidate` to return `ShouldSwitch` for that fork, triggering chain selection to prefer it over the honest chain. This bypasses the entire Peras committee/quorum/BLS-signature security model.

---

### Likelihood Explanation

**Medium.** Peras is under active development and the object diffusion infrastructure is wired up in the codebase. The vulnerability is reachable on any private testnet or development deployment where Peras certificate diffusion is enabled. The stub is a global overlapping instance, so no per-era override is in place. The attacker needs only a standard NTN connection — no keys, no stake, no privileged access. The only mitigating factor is that Peras is not yet active on Cardano mainnet; however, the code is present and the path is fully reachable in a private-testnet sequence.

---

### Recommendation

1. Remove or gate the global stub instance. The `instance StandardHash blk => BlockSupportsPeras blk` must not be reachable in any code path that processes network-supplied certificates. Replace it with a compile-time error or a `newtype`-wrapped disabled instance.
2. Until a real `validatePerasCert` implementation is in place (tracking issue `cardano-peras/issues/120`), the `processCerts` ingest path must refuse all inbound certificates rather than accepting them unconditionally.
3. The `PerasCert` data type in the stub instance carries no cryptographic fields. Any real instance must include the BLS aggregate signature (as in `Ouroboros.Consensus.Peras.Cert.V1.PerasCert`) and verify it against the committee's aggregate public key before returning `Right`.

---

### Proof of Concept

On a private testnet with Peras certificate diffusion enabled:

1. Connect a malicious peer to the target node via the standard NTN object diffusion mini-protocol.
2. Craft a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point on attacker fork>`.
3. Send the certificate batch to the target node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is stored in `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. `implGetWeightSnapshot` now returns a non-empty `PerasWeightSnapshot` mapping the attacker's block to `perasWeight params`.
7. On the next chain selection event, `preferAnchoredCandidate` enters the Peras weighted path and computes `weightedSelectView` for both chains. The attacker's fork, boosted by the injected certificate, is preferred over the honest chain.
8. The node switches to the attacker's fork. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
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
