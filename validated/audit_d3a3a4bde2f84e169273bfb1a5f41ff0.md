### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, which applies to **all** block types via a catch-all instance, implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) without performing any cryptographic or structural validation. This stub is wired directly into the production `processCerts` function that handles Peras certificates received from remote peers. An unprivileged peer can send any crafted certificate, which will pass "validation" and be stored in the `PerasCertDB`, triggering chain selection for the attacker-chosen boosted block.

---

### Finding Description

**Root cause — always-succeeding certificate validator:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` at lines 318–358, a catch-all instance is declared for every block type:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

No signature check, no committee membership check, no round-number sanity check — the function returns `Right` for every input.

**Production call site — `processCerts` uses the stub directly:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` at lines 118–133, the production pool writer for the `ChainDB` is constructed with this stub as the sole validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← stub, always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    }
```

`processCerts` (lines 156–185 of the same file) partitions the results of `validateCert <$> certsNotAlreadyInDb`. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is stored.

**Chain selection is triggered on every accepted certificate:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs` at lines 483–532, `chainSelSync` processes each stored certificate. After a single age check (slot vs. immutable tip), it calls:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

`noPunishment` means the peer suffers no consequence even if the triggered chain selection fails. The boosted block's chain is re-evaluated with the additional certificate weight, potentially causing the node to switch away from the canonical chain.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that names any block currently in the node's `VolatileDB` as the "boosted block." Because `validatePerasCert` never rejects anything, the certificate is stored and chain selection is re-run with the artificial boost applied to the attacker-chosen block. If that block sits on a fork that is otherwise lighter than the canonical chain, the boost can tip the balance and cause the honest node to adopt the non-canonical fork. This is a **chain selection manipulation** attack: an unprivileged peer can make an honest node prefer a less-secure chain beyond the intended Ouroboros security assumptions.

Impact class: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

---

### Likelihood Explanation

The `ObjectDiffusion` mini-protocol for Peras certificates is reachable by any peer that connects to the node. No keys, stake, or operator access are required. The attacker only needs to know the hash and slot of a block currently in the target node's `VolatileDB` (obtainable via `ChainSync`). The attack is repeatable with no per-attempt cost because `noPunishment` is used.

---

### Recommendation

1. **Do not ship `makePerasCertPoolWriterFromChainDB` (or `makePerasCertPoolWriterFromCertDB`) in a production release until `validatePerasCert` performs real cryptographic and committee-membership validation.** The TODO at issue [#120](https://github.com/tweag/cardano-peras/issues/120) must be resolved first.
2. Guard the Peras certificate diffusion path behind a feature flag that is disabled by default until the real validator is in place.
3. Add a compile-time or runtime assertion that the degenerate catch-all instance is never used on the production `HardForkBlock` type.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the `ObjectDiffusion` mini-protocol for Peras certificates.
2. Obtain the `Point` (slot + hash) of a block on a competing fork currently in the node's `VolatileDB` (via `ChainSync`).
3. Construct a `PerasCert` with `pcCertBoostedBlock = <that Point>` and any `pcCertRound` not already in the node's `PerasCertDB`.
4. Send the certificate to the node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
6. The certificate is stored via `ChainDB.addPerasCertAsync`.
7. `chainSelSync` fires `chainSelectionForBlock` for the boosted block with `noPunishment`.
8. The node re-evaluates chain selection with the artificial boost; if the fork's boosted weight now exceeds the canonical chain's weight, the node switches to the attacker-chosen fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
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
    pure $ addedCertRes
```
