### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` degenerate instance implements `validatePerasCert` as a stub that unconditionally returns `Right ValidatedPerasCert` for every input, performing zero cryptographic or structural checks. This stub is wired directly into the production Peras certificate diffusion inbound pipeline via `makePerasCertPoolWriterFromChainDB`. Any unprivileged peer can send a crafted `PerasCert` over the Peras cert diffusion mini-protocol; the certificate will pass "validation," be stored in the `PerasCertDB`, and trigger chain selection with an attacker-controlled boost weight, potentially causing the honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The degenerate `BlockSupportsPeras` instance, explicitly marked as a temporary placeholder, implements `validatePerasCert` as:

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

No signature is verified, no voter eligibility is checked, no quorum threshold is enforced, and no round-number bounds are validated. Every certificate, regardless of content, is promoted to `ValidatedPerasCert`. [1](#0-0) 

**Production wiring — `makePerasCertPoolWriterFromChainDB`:**

The production pool writer for inbound Peras certificates received from peers calls this stub directly:

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

**Inbound processing — `processCerts`:**

`processCerts` calls `validateCert` (bound to the stub above) on every certificate received from a peer. If all certificates pass (which they always do), each is timestamped and forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Chain selection trigger — `chainSelSync` / `ChainSelAddPerasCert`:**

Once stored, the certificate is passed to `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` then uses the certificate's `vpcCertBoost` (set to `perasWeight params` by the stub) to boost the weight of the attacker-nominated block and triggers `chainSelectionForBlock`:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Mini-protocol entry point:**

The Peras cert diffusion client/server handlers are registered in the node-to-node `Handlers` record, making this reachable from any connecting peer:

```haskell
, hPerasCertDiffusionClient :: ...
, hPerasCertDiffusionServer :: ...
``` [5](#0-4) 

---

### Impact Explanation

**Severity: High — Chain selection manipulation by an unprivileged peer.**

An attacker operating as a normal peer can craft a `PerasCert` that names any block currently in the victim node's VolatileDB as the "boosted" block. Because `validatePerasCert` accepts it unconditionally, the certificate is stored and its `perasWeight`-sized boost is applied to that block during chain selection. If the boosted block is on a weaker fork, the honest node may switch away from the canonical chain to the attacker-preferred fork. This directly matches the allowed impact category: *"chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The `PerasCert` data type in the degenerate instance carries only `pcCertRound` and `pcCertBoostedBlock` — no signature field exists to forge; the attacker simply supplies any round number and any block point. [6](#0-5) 

---

### Likelihood Explanation

**Likelihood: Medium-High.** The Peras cert diffusion mini-protocol is wired into the production node-to-node handler set. Any peer that can establish a connection can send certificates. The only mitigating factor is that Peras may not yet be activated on mainnet; however, the code is present and the handlers are registered, so any private testnet or pre-production deployment running this codebase is immediately exploitable without any privileged access.

---

### Recommendation

1. **Do not ship `validatePerasCert` as a stub in any deployment where the Peras cert diffusion protocol is enabled.** The stub must be replaced with a real implementation that verifies the aggregate BLS signature, checks voter eligibility against the committee, and enforces quorum before promoting a certificate to `ValidatedPerasCert`.
2. Until the real implementation is ready, gate the Peras cert diffusion mini-protocol behind a feature flag that is disabled by default, so that the stub is never reachable from an external peer.
3. The same applies to `validatePerasVote`, which also carries a `TODO` comment and performs only a stake-lookup check without verifying the BLS vote signature. [7](#0-6) 

---

### Proof of Concept

**Attacker-controlled entry path (no privileged access required):**

1. Attacker connects to the victim node as a normal peer via the node-to-node protocol.
2. Attacker identifies a block `B_fork` in the victim's VolatileDB that is on a weaker fork (e.g., via the ChainSync protocol).
3. Attacker constructs a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = point(B_fork)`.
4. Attacker sends this certificate via the Peras cert diffusion mini-protocol (`hPerasCertDiffusionClient` / `hPerasCertDiffusionServer`).
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
6. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` is called.
7. `chainSelSync` processes `ChainSelAddPerasCert`, finds `B_fork` in the VolatileDB, and calls `chainSelectionForBlock` with the boosted weight.
8. Chain selection now considers `B_fork`'s chain to have additional Peras weight equal to `perasWeight mkPerasParams`, potentially causing the node to switch to the attacker's preferred fork. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L233-250)
```haskell
  , hPerasCertDiffusionClient ::
      NodeToNodeVersion ->
      ControlMessageSTM m ->
      ConnectionId addr ->
      PerasCertDiffusionInboundPipelined blk m ()
  , hPerasCertDiffusionServer ::
      NodeToNodeVersion ->
      ConnectionId addr ->
      PerasCertDiffusionOutbound blk m ()
  , hPerasVoteDiffusionClient ::
      NodeToNodeVersion ->
      ControlMessageSTM m ->
      ConnectionId addr ->
      PerasVoteDiffusionInboundPipelined blk m ()
  , hPerasVoteDiffusionServer ::
      NodeToNodeVersion ->
      ConnectionId addr ->
      PerasVoteDiffusionOutbound blk m ()
```
