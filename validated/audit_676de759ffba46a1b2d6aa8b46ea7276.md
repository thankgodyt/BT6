### Title
Unconditional `validatePerasCert` Acceptance Enables Unauthorized Peras Certificate Injection and Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This stub is wired directly into the production Peras certificate diffusion inbound handler. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted-block pointer; the node will accept it as fully validated and feed it into chain selection, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validator always succeeds:**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase, covering all `StandardHash blk`) implements `validatePerasCert` as:

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

No signature check, no round-number bounds check, no committee membership check, no quorum check — the function wraps any input cert in `Right` and returns it as `ValidatedPerasCert`.

**Production wiring — stub is the live validator:**

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound cert and, if all pass, adds them to the ChainDB: [3](#0-2) 

**Network entry point — reachable by any peer:**

The production node-to-node handler wires `makePerasCertPoolWriterFromChainDB` directly into the Peras certificate diffusion inbound mini-protocol:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**Chain-selection side-effect:**

Once a `ValidatedPerasCert` is added to the `PerasCertDB` via `ChainDB.addPerasCertAsync`, `chainSelSync` triggers `chainSelectionForBlock` for the cert's `boostedBlock`. If that block is present in the VolatileDB, the node re-evaluates chain selection with the additional Peras boost weight applied to the attacker-chosen block: [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block in the victim node's VolatileDB as the `pcCertBoostedBlock` and any `pcCertRoundNo`. Because `validatePerasCert` never rejects any certificate, the node accepts it as authoritative and re-runs chain selection with the artificial Peras boost applied to the attacker-chosen block. This can cause the node to switch away from the canonical chain to a less-secure or non-canonical fork, constituting a **High** chain-selection integrity failure: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is an open peer-to-peer channel; no authentication or stake proof is required to connect and send certificates. The stub validator contains an explicit `TODO` comment acknowledging that validation is not yet implemented. Any peer that can establish a node-to-node connection can exploit this immediately.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS signature over the certificate's `(electionId, candidate)` pair against the claimed committee members' public keys.
2. That the set of claimed voters meets the quorum threshold for the given round.
3. That each claimed voter was actually elected to the committee for that round (VRF eligibility proof).

Until real validation is implemented, the inbound certificate diffusion handler should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.

---

### Proof of Concept

1. Attacker node connects to victim via the Peras certificate diffusion mini-protocol (`hPerasCertDiffusionClient`).
2. Attacker sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = P }` where `P` is the point of a block on a minority fork known to be in the victim's VolatileDB.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
5. `ChainDB.addPerasCertAsync` stores the cert; `chainSelSync` fires `chainSelectionForBlock` for block `P`.
6. Chain selection now scores the fork containing `P` with the additional Peras boost weight, potentially causing the victim to switch to the attacker-chosen fork.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```
