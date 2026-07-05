### Title
`validatePerasCert` Unconditionally Accepts Any Certificate Without Cryptographic Verification, Enabling Unprivileged Peers to Manipulate Chain Selection via Fraudulent Peras Boosts — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal degenerate `BlockSupportsPeras` instance, which applies to all block types including production `CardanoBlock`, implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound Peras certificate without performing any cryptographic or structural validation. The production certificate-ingestion path (`makePerasCertPoolWriterFromChainDB` → `processCerts`) calls this stub directly on peer-supplied data. An unprivileged peer can therefore inject a crafted certificate boosting any block in the VolatileDB, triggering chain selection with an artificial weight boost and causing the honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — missing validation in the degenerate instance:**

In `SupportsPeras.hs` the only `BlockSupportsPeras` instance is a catch-all:

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
``` [1](#0-0) 

No more-specific instance exists for `CardanoBlock`, so this stub is the live implementation. The function unconditionally returns `Right` — every certificate, regardless of its round number, boosted-block pointer, or any cryptographic proof, is stamped as `ValidatedPerasCert` and assigned the full `perasWeight` boost.

**Production call path:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` directly as the validation callback passed to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions the batch into valid/invalid using the supplied `validateCert` callback. Because the callback always returns `Right`, every certificate in every batch is classified as valid and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` then processes it: it looks up the boosted block in the VolatileDB and, if found, calls `chainSelectionForBlock` with the certificate's weight applied: [4](#0-3) 

**Analogous gap to the external report:**

The external report's `SetDenylist` lacked `has_one = owner` — a single required authorization check that was simply absent. Here, `validatePerasCert` is the required cryptographic authorization check for Peras certificates, and it is entirely absent (replaced by an unconditional `Right`). Any peer that can reach the Peras certificate diffusion miniprotocol occupies the role of the "any user" attacker in the external report.

### Impact Explanation

**Impact: High — chain selection manipulation by an unprivileged peer.**

A malicious peer sends a crafted `PerasCert` naming any block hash currently in the target node's VolatileDB as `pcCertBoostedBlock`. Because `validatePerasCert` always succeeds, the certificate is stored and chain selection is re-run with the full `perasWeight` boost applied to that block's chain. If the boosted chain was previously non-preferred (e.g., a shorter fork), the artificial boost can flip the node's selection to a non-canonical chain, violating the chain-selection invariant that only legitimately certified blocks receive weight boosts. This falls squarely within the allowed scope: *"chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

**Likelihood: Medium.**

The Peras certificate diffusion miniprotocol infrastructure is fully wired into the production `ChainDB` and `ObjectDiffusion` layer. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase. The TODO comments (`cardano-peras/issues/73`, `cardano-peras/issues/120`) confirm this is a known placeholder, not a deliberate design choice. Any node that has the Peras cert miniprotocol enabled and accepts peer connections is reachable by an unprivileged attacker with no keys or special privileges. The attacker only needs to know a valid block hash in the target's VolatileDB (obtainable via ChainSync).

### Recommendation

Replace the unconditional `Right` stub with a real implementation that:
1. Verifies the certificate's aggregate BLS signature against the claimed voter set and the `(roundNo, boostedBlock)` message (mirroring `implVerifyCert` in `EveryoneVotes.hs` / `WFALS.hs`).
2. Checks that all claimed voters are registered in the current stake distribution with positive stake.
3. Checks that the aggregate stake of the voter set meets the quorum threshold.

Until the real implementation is ready, the degenerate instance should reject all certificates (`Left PerasValidationErr`) rather than accept them, so that the stub is safe-by-default. The `processCerts` function already has the correct rejection logic — the only missing piece is a non-trivial `validateCert` callback. [5](#0-4) 

### Proof of Concept

1. Connect to a target node that has the Peras cert miniprotocol active.
2. Obtain any block hash `H` currently in the node's VolatileDB (e.g., via ChainSync headers).
3. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point with hash H>`.
4. Send the certificate to the node via the Peras cert diffusion miniprotocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..}` unconditionally.
6. The certificate is added to `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
7. `chainSelSync` finds block `H` in the VolatileDB and calls `chainSelectionForBlock` with the Peras weight boost.
8. If the chain containing `H` was previously non-preferred, the node switches to it — chain selection has been manipulated by an unprivileged peer with no keys.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
