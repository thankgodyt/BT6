### Title
Peras Certificate Validation is a No-Op Stub, Allowing Any Peer to Inject Fake Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or structural validation. Any unprivileged peer connected via the ObjectDiffusion mini-protocol can send a crafted `PerasCert` pointing to any block in the VolatileDB. The certificate is accepted, stored in the `PerasCertDB`, and its `PerasWeight` boost is applied during chain selection via `WeightedSelectView`, potentially causing the node to prefer a non-canonical fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a permanent no-op:** [1](#0-0) 

The universal instance `instance StandardHash blk => BlockSupportsPeras blk` is the only instance in the codebase. Its `validatePerasCert` implementation ignores all certificate content and always returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`. The `PerasValidationErr` data type has a single constructor `PerasValidationErr` with no fields, and the TODO comment explicitly acknowledges that actual validation is absent (tracked in issue #120).

**Production inbound path — `makePerasCertPoolWriterFromChainDB`:** [2](#0-1) 

This is the production writer used by the ObjectDiffusion mini-protocol. It calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. Because `validatePerasCert` always returns `Right`, every inbound certificate from every peer passes validation.

**`processCerts` — validation gate that never fires:** [3](#0-2) 

`partitionEithers (validateCert <$> certsNotAlreadyInDb)` always produces an empty error list, so the `([], validatedCerts)` branch is always taken and every certificate is added via `addCert`.

**Chain selection impact — fraudulent weight boost applied:** [4](#0-3) 

`wsvTotalWeight` sums `BlockNo` and `wsvWeightBoost`. The default `perasWeight` is `PerasWeight 15`, meaning a single injected certificate adds 15 block-lengths of weight to the boosted block's chain. This is applied in `preferAnchoredCandidate` during chain selection. [5](#0-4) 

**Chain selection triggered by injected certificate:** [6](#0-5) 

When the boosted block is present in the VolatileDB, `chainSelectionForBlock` is called for it, re-evaluating whether the fork containing that block is now preferred over the current selection — using the fraudulent weight.

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` with `pcCertBoostedBlock` pointing to any block in the target node's VolatileDB. Because `validatePerasCert` performs no validation (no signature check, no committee membership check, no quorum proof), the certificate is accepted and stored. The `PerasWeight 15` boost is then applied to that block's chain during `preferAnchoredCandidate`. A fork that is 14 blocks shorter than the honest chain becomes preferred. This is a **bypass of Peras certificate/vote verification checks enabling unauthorized certificate acceptance**, directly causing a **chain selection error** where an honest node prefers a non-canonical, less-secure chain.

---

### Likelihood Explanation

The attack requires only a network connection to the target node via the ObjectDiffusion mini-protocol, which is a standard node-to-node protocol. No keys, stake, or privileged access are required. The `PerasCert` wire format is simple (round number + block point) and trivially constructable. The vulnerability is active whenever Peras is enabled. The CHANGELOG confirms Peras is disabled by default but is the intended production state; the production code path (`makePerasCertPoolWriterFromChainDB`) is fully wired in `ChainDB.Impl` and ready to process inbound certificates. [7](#0-6) 

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before enabling Peras in production. At minimum, validate the committee quorum proof and cryptographic signatures over the certificate content. The stub must not be shipped as the live validator.
2. **Do not use the universal `instance StandardHash blk => BlockSupportsPeras blk`** as the production instance. Provide a concrete, era-specific instance with real validation logic.
3. **Gate the ObjectDiffusion certificate inbound path** on Peras being enabled, and ensure the validator passed to `processCerts` is the real one, not `validatePerasCert mkPerasParams` with a stub implementation.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to an honest node via the ObjectDiffusion mini-protocol (standard N2N connection, no privileges required).
2. Attacker sends a batch containing one `PerasCert`:
   - `pcCertRound = PerasRoundNo <any_round_not_yet_in_db>`
   - `pcCertBoostedBlock = BlockPoint <slot> <hash_of_block_on_attacker_fork_in_volatiledb>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
4. Certificate is added to `PerasCertDB` via `addCert`.
5. `ChainSelAddPerasCert` message is enqueued; `chainSelSync` processes it.
6. The boosted block is found in the VolatileDB; `chainSelectionForBlock` is called.
7. `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork: `BlockNo(fork_tip) + 15`. If the honest chain tip has `BlockNo(honest_tip) < BlockNo(fork_tip) + 15`, the node switches to the attacker's fork.

**Concrete threshold:** With `perasWeight = 15`, a fork that is up to 14 blocks shorter than the honest chain becomes preferred after a single injected certificate. The attacker needs only to have previously diffused a valid block header (accepted by ChainSync header validation) onto the fork to have a target block in the VolatileDB. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-532)
```haskell
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
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs (L307-307)
```haskell
            , addPerasCertAsync = getEnv1 h ChainSel.addPerasCertAsync
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
