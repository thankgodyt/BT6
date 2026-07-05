### Title
Peras Certificate Validation Bypass: Degenerate `validatePerasCert` Unconditionally Accepts Any Forged Certificate from an Unprivileged Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance for all `StandardHash blk` types implements `validatePerasCert` as an unconditional `Right` — it performs zero cryptographic or committee-membership checks and wraps any inbound certificate as `ValidatedPerasCert`. The production node-to-node handler `hPerasCertDiffusionClient` in `mkHandlers` is wired directly to `makePerasCertPoolWriterFromChainDB`, which passes this stub validator to `processCerts`. Any unprivileged peer can therefore send a crafted `PerasCert` that passes "validation", is stored in the `PerasCertDB`, and triggers chain selection for an arbitrary boosted block, potentially causing the honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The instance comment reads `"TODO: degenerate instance for all blks to get things to compile"`. The implementation:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No signature is verified, no committee membership is checked, no round-number bounds are enforced. Every certificate, regardless of origin or content, is returned as `ValidatedPerasCert`.

**Production wiring — the stub is used in the live node-to-node handler:**

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validator: [2](#0-1) 

This writer is handed directly to `hPerasCertDiffusionClient` inside `mkHandlers`, the production node-to-node handler factory: [3](#0-2) 

**Inbound processing — forged cert reaches chain selection:**

`processCerts` calls `validateCert` on each inbound cert. Since the stub always returns `Right`, every cert passes: [4](#0-3) 

The validated cert is then passed to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it, adds the cert to `PerasCertDB`, and calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

The boosted block now carries extra `PerasWeight` in chain selection, which can cause the node to switch to a fork it would otherwise not prefer.

---

### Impact Explanation

**Severity: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

A peer with no stake and no committee credentials can craft a `PerasCert` claiming to boost any block in the volatile DB. Because `validatePerasCert` never rejects anything, the cert is stored and chain selection is re-run with the artificial boost applied. If the boosted block is on a minority fork, the honest node may switch to that fork, diverging from the canonical chain. This directly violates the Peras security invariant that only a quorum of legitimate committee members can boost a block.

---

### Likelihood Explanation

**High.** The `hPerasCertDiffusionClient` miniprotocol is active in every production node-to-node connection (wired unconditionally in `mkHandlers`). Any peer that speaks the `PerasCertDiffusion` protocol can send a batch of crafted certificates. The attacker needs only a valid network connection — no stake, no keys, no privileged access. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase (it is a catch-all `instance StandardHash blk =>`), so there is no per-era override that would restore real validation.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature against the declared committee members' verification keys.
2. Checks that the declared voters form a quorum (total stake above threshold) in the current committee.
3. Validates the round number is within the acceptable window.

Until the real implementation is ready, the `hPerasCertDiffusionClient` handler should either be disabled or should reject all inbound certificates at the protocol level, rather than silently accepting them through a no-op validator. [6](#0-5) 

---

### Proof of Concept

**Attacker preconditions:** A network peer that can speak the `PerasCertDiffusion` miniprotocol (any node-to-node connection).

**Step-by-step exploit path:**

1. Attacker connects to an honest node and negotiates the `PerasCertDiffusion` protocol via `aPerasCertDiffusionClient`.
2. Attacker sends a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on a minority fork>`.
3. The honest node's `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the validator.
4. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally. [7](#0-6) 
5. `processCerts` calls `addCert` → `ChainDB.addPerasCertAsync`, enqueuing `ChainSelAddPerasCert`.
6. `chainSelSync` adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block. [8](#0-7) 
7. Chain selection now considers the minority-fork block as boosted by `perasWeight` extra weight, potentially causing the honest node to switch to the attacker-chosen fork.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
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
