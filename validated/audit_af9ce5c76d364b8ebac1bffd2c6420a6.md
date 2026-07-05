### Title
`validatePerasCert` Stub Unconditionally Accepts Any Inbound Peras Certificate, Enabling Fraudulent Chain-Weight Injection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a deliberate stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum validation. Because `makePerasCertPoolWriterFromChainDB` — the production object-diffusion writer — passes this stub directly as the validation callback, any unprivileged peer can inject an arbitrary `PerasCert` (with any round number and any boosted-block point) into a node's `PerasCertDB`. The accepted certificate then triggers `chainSelectionForBlock`, inflating the Peras weight of the attacker-chosen block and potentially causing the honest node to switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` is the only `BlockSupportsPeras` instance in the codebase. Its `validatePerasCert` body is:

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

No signature is checked, no committee membership is verified, no quorum proof is examined. Every certificate is unconditionally promoted to `ValidatedPerasCert`. [1](#0-0) 

**Production inbound path — `makePerasCertPoolWriterFromChainDB`:**

The object-diffusion writer that handles certificates received from network peers passes this stub as the `validateCert` callback:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← stub, always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

**`processCerts` accepts the batch and forwards to `addPerasCertAsync`:**

`processCerts` calls `validateCert` on each new certificate; if all return `Right`, every certificate is timestamped and forwarded to `addCert` (i.e., `ChainDB.addPerasCertAsync`). Because the stub never returns `Left`, the "reject the whole batch" branch is unreachable. [3](#0-2) 

**`chainSelSync` uses the fraudulent certificate to trigger chain selection:**

`addPerasCertAsync` enqueues the certificate; `chainSelSync` dequeues it, stores it in `PerasCertDB`, and calls `chainSelectionForBlock` for the attacker-specified boosted block:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Weight boost is applied during chain comparison:**

`chainSelectionForBlock` reads the `PerasWeightSnapshot` (which now includes the fraudulent boost) and uses `totalWeightOfFragment` / `preferAnchoredCandidate` to decide whether to switch chains. A fork containing the attacker-boosted block now appears heavier than the honest chain. [5](#0-4) [6](#0-5) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert{pcCertRound = r, pcCertBoostedBlock = p}` pointing to any block `p` in the node's VolatileDB.
2. Send it via the object-diffusion mini-protocol.
3. The node accepts it without any validation, stores it, and re-runs chain selection with the fraudulent weight boost applied to `p`.
4. If `p` is on a fork, the fork's total weight (`blockNo + boost`) may now exceed the honest chain's weight, causing the node to switch.

This is a **chain-selection manipulation** attack: an unprivileged peer can make an honest node prefer a non-canonical chain by injecting fake Peras weight. This directly undermines the Ouroboros Peras security guarantee that only a quorum-certified block earns a weight boost.

**Severity: High** — matches "Bypass of … certificate … checks … that enables unauthorized … certificate acceptance" and "chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."

---

### Likelihood Explanation

- No privileged access is required; any connected peer can send a `PerasCert` object via the object-diffusion mini-protocol.
- The exploit requires only that Peras is enabled (via `rnFeatureFlags`), which is the intended production state for Peras-supporting eras.
- The attacker needs a block hash present in the target node's VolatileDB (easily obtained via ChainSync) to trigger the chain-selection re-evaluation.
- The attack is deterministic and repeatable with no brute-force component.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS/committee signature on the certificate against the known committee for round `pcCertRound`.
2. Confirms the certificate was produced by a quorum of eligible committee members (weighted stake ≥ threshold).
3. Checks that `pcCertBoostedBlock` is a valid, known block point.
4. Rejects certificates whose round number is outside the acceptable window.

Until the real implementation is in place, the object-diffusion inbound path (`makePerasCertPoolWriterFromChainDB`) should refuse to accept externally received certificates (or gate the entire Peras cert diffusion path behind the feature flag so that no external input reaches `processCerts` when validation is not yet implemented).

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Peer A connects to honest node N.
2. Peer A sends a single-element batch `[PerasCert{pcCertRound=42, pcCertBoostedBlock=<hash of fork block F>}]` via the object-diffusion protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` unconditionally.
4. `ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` stores it in `PerasCertDB` and calls `chainSelectionForBlock` for block `F`.
5. `getPerasWeightSnapshot` now returns a snapshot that includes the boost for `F`; `totalWeightOfFragment` for the fork containing `F` increases by `perasWeight params`.
6. If the fork's boosted weight exceeds the honest chain's weight, node N switches to the fork — a chain-selection manipulation achieved with zero cryptographic material. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
