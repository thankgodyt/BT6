### Title
Peras Certificate Verification Bypass via Stub `validatePerasCert` Always Returning Success — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance for all block types implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. This stub is the active implementation used in production code paths that process inbound Peras certificates from unprivileged peers. Any peer can inject arbitrary Peras certificates that will be accepted without verification, and those certificates directly influence chain selection via Peras weight boosts.

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the gate for accepting inbound Peras certificates. The only deployed instance is a catch-all degenerate instance that always succeeds: [1](#0-0) 

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

This stub is directly wired into the inbound certificate processing path in `processCerts`: [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validator, and `processCerts` calls it on every inbound certificate not already in the database: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate passes, is timestamped, and is forwarded to `ChainDB.addPerasCertAsync`. Accepted certificates are stored in the `PerasCertDB` and their weight boosts are incorporated into `PerasWeightSnapshot`, which is consulted during chain selection: [4](#0-3) 

Chain selection uses `preferAnchoredCandidate` with the weight snapshot, meaning forged certificates with arbitrary `pcCertBoostedBlock` values can artificially elevate any block's weight: [5](#0-4) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block hash. Because `validatePerasCert` performs no cryptographic or eligibility checks, the certificate is accepted as `ValidatedPerasCert` and assigned the full `perasWeight` boost. This constitutes a **bypass of Peras certificate verification** that enables unauthorized certificate acceptance. The injected weight boost can cause an honest node to prefer a non-canonical or adversarially chosen chain over the legitimate chain, directly violating chain selection correctness under the Peras security model.

**Impact category:** Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.

### Likelihood Explanation

The attack requires only the ability to connect as a peer and send messages via the Peras object-diffusion miniprotocol — no keys, stake, or privileged access are needed. The `opwAddObjects` handler is invoked for every batch of inbound certificates, and the deduplication check (by `PerasRoundNo`) is the only gate before the always-succeeding validator. An attacker can inject one certificate per round number, covering an unbounded range of rounds. Likelihood is **medium-high** once the Peras miniprotocol is active on production nodes.

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic and semantic validation before the Peras object-diffusion miniprotocol is enabled on production nodes. At minimum, the implementation must verify:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed committee's aggregate verification key.
2. That the claimed voters constitute a valid quorum per the current stake distribution.
3. That `pcCertRound` falls within the expected window relative to the current chain tip.

Until real validation is in place, the Peras certificate inbound path should be disabled or gated behind a feature flag that is off by default in production builds.

### Proof of Concept

1. Connect to a target node as a peer with the Peras object-diffusion miniprotocol enabled.
2. Craft a `PerasCert blk` with `pcCertRound = R` (any round not yet in the DB) and `pcCertBoostedBlock = <hash of target block>`.
3. Send the certificate via `opwAddObjects`.
4. `processCerts` reads `alreadyInDb` (does not contain `R`), calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert cert (perasWeight mkPerasParams))`.
5. The certificate is added via `ChainDB.addPerasCertAsync`; `implGetWeightSnapshot` now returns a snapshot boosting `<hash of target block>`.
6. On the next chain selection event, `preferAnchoredCandidate` uses the inflated weight, potentially switching the node to the attacker-chosen chain. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```
