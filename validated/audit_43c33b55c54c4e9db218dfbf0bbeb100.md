### Title
Unconditional `validatePerasCert` Acceptance Allows Unprivileged Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that always returns `Right` — accepting every certificate without performing any cryptographic or semantic check. An unprivileged peer can send a crafted `PerasCert` over the ObjectDiffusion mini-protocol; it will pass "validation", be stored in the `PerasCertDB`, and trigger chain selection with artificially boosted Peras weight for an attacker-chosen block.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must approve an inbound certificate before it enters the node's state. The only instance in the production codebase is the degenerate catch-all instance at: [1](#0-0) 

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

No Cardano-specific override exists anywhere in the repository (confirmed: `BlockSupportsPeras` appears only in `SupportsPeras.hs`, `TestBlock.hs`, and a state-machine test file). This degenerate instance is therefore the live production implementation.

The inbound certificate pipeline in `processCerts` calls this function directly: [2](#0-1) [3](#0-2) 

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

`processCerts` partitions results into errors and successes; because `validatePerasCert` never produces a `Left`, every certificate from every peer is unconditionally forwarded to `addCert`: [4](#0-3) 

Once stored, `chainSelSync` processes the certificate and calls `chainSelectionForBlock` for the attacker-chosen boosted block: [5](#0-4) 

The Peras boost weight (`perasWeight params`) is applied to the attacker-specified `pcCertBoostedBlock`, directly influencing which chain the node selects as canonical.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as `pcCertBoostedBlock` and any `pcCertRound`. Because `validatePerasCert` unconditionally returns `Right`, the certificate is stored and its boost weight is applied during chain selection. This allows the attacker to make an honest node prefer a non-canonical or adversarially-chosen chain over the legitimate best chain — a direct chain-selection safety failure. No quorum, no aggregate signature, no committee eligibility, and no round-number plausibility is checked.

**Impact class**: Critical — bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a standard network-facing endpoint reachable by any peer. The attack requires only the ability to connect to the node and send a well-formed (but cryptographically fabricated) `PerasCert` CBOR message. No keys, no stake, no prior relationship is needed. The stub is the only instance in the codebase, so every deployed node is affected.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:

1. The certificate's aggregate BLS signature over the claimed voter set.
2. That the voter set constitutes a valid quorum (sufficient stake) for the claimed round.
3. That each voter was eligible for the committee in that round (VRF/sortition proof).
4. That `pcCertRound` is within the acceptable window relative to the current chain tip.

Until a real Cardano-specific `BlockSupportsPeras` instance is provided, the degenerate instance should at minimum reject all inbound certificates (return `Left PerasValidationErr`) rather than accept them all, so that the network-facing path is closed until proper validation is implemented.

---

### Proof of Concept

A peer constructs a `PerasCert` with an attacker-chosen `pcCertBoostedBlock` pointing to a block on a minority fork and sends it via the ObjectDiffusion mini-protocol:

```
-- Attacker-controlled peer sends:
PerasCert
  { pcCertRound      = <any round number>
  , pcCertBoostedBlock = <hash of a block on the attacker's fork>
  }
```

Execution trace through production code:

1. `makePerasCertPoolWriterFromChainDB` receives the cert batch. [6](#0-5) 

2. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right validatedCert`. [4](#0-3) 

3. `validatePerasCert` stub — no checks performed, unconditional success. [7](#0-6) 

4. `ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` processes it and calls `chainSelectionForBlock` with the attacker's boosted block, applying `perasWeight` to that block's chain. [8](#0-7) 

Result: the honest node now considers the attacker's fork to have additional Peras certificate weight and may switch to it, diverging from the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L487-532)
```haskell
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
