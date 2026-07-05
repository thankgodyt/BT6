### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Fraudulent Peras Certificates into Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that returns `Right` for every certificate it receives, performing zero cryptographic or authorization checks. Because this function is the sole validation gate in the live `PerasCertDiffusion` inbound mini-protocol handler, any unprivileged peer can send a crafted `PerasCert` that is accepted without verification and fed directly into chain selection, where it applies a Peras weight boost to an arbitrary block.

---

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the method responsible for verifying that an incoming Peras certificate is legitimate before it is stored and used to influence chain selection. The universal instance that covers all block types implements this method as a no-op stub:

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

The stub skips every check that a real implementation must perform:
- No verification of the aggregate BLS signature over the claimed voters
- No check that the claimed voter seat indices are actual committee members in the current epoch's stake distribution
- No check that the certificate's `pcCertRound` is valid for the current Peras context
- No check that `pcCertBoostedBlock` is a block that exists on any known chain

The `ValidatedPerasCert` wrapper is the type-level proof that validation succeeded; the stub manufactures this proof unconditionally.

This stub is wired directly into the live inbound certificate handler. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
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

`processCerts` treats any `Right` result as a fully validated certificate and immediately passes it to `addCert` (here `ChainDB.addPerasCertAsync`): [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` is the writer used by the production NtN handler `hPerasCertDiffusionClient`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

Once `addPerasCertAsync` is called, `chainSelSync` processes the certificate. It calls `chainSelectionForBlock` for the boosted block, potentially switching the node to a fork that carries the fraudulent certificate's weight boost: [5](#0-4) 

The `addPerasCertAsync` API contract explicitly states: *"If this leads to a fork to be weightier than our current selection, this will trigger a fork switch."* [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and any round number, send it over the `PerasCertDiffusion` mini-protocol, and have the receiving node:

1. Accept it as `ValidatedPerasCert` without any cryptographic check
2. Store it in the `PerasCertDB`
3. Trigger `chainSelectionForBlock` for the boosted block

Because Peras certificates apply a `perasWeight` boost to a block's chain weight, a fraudulent certificate can make a minority fork appear heavier than the honest chain, causing the node to switch away from the canonical chain. This is a **chain selection safety failure** driven entirely by unauthenticated peer input. The `ValidatedPerasCert` type wrapper provides a false guarantee of legitimacy throughout the rest of the system.

---

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is fully wired into the production NtN handler stack in `NodeToNode.hs`. Any peer that establishes a standard NtN connection can send `PerasCert` messages. No stake, no key material, and no prior relationship is required. The attack requires only the ability to connect to the node and send a single crafted protocol message. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm the stub is a known placeholder, but it is currently active in the production code path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature against the declared voters' public keys (using `implVerifyCert` from `WFALS` or `EveryoneVotes` as the model)
2. Checks that every declared voter seat index is a legitimate committee member in the current epoch's stake distribution
3. Verifies that `pcCertRound` falls within the valid range for the current Peras context
4. Verifies that `pcCertBoostedBlock` is a known block

Until the real implementation is ready, the stub should reject all certificates (`Left PerasValidationErr`) rather than accept all of them, so that the inbound handler disconnects peers sending unverifiable certificates rather than acting on them.

---

### Proof of Concept

**Setup**: A private testnet with two nodes, A (honest) and B (attacker). Node B connects to A via the standard NtN protocol.

**Steps**:

1. Node B identifies a block hash `h` on a minority fork that it wants node A to prefer.
2. Node B constructs a `PerasCert` with `pcCertBoostedBlock = h` and any `pcCertRound` not yet seen by A:
   ```haskell
   PerasCert { pcCertRound = someRound, pcCertBoostedBlock = someBlockPoint }
   ```
3. Node B sends this certificate to node A via the `PerasCertDiffusion` mini-protocol.
4. Node A's `hPerasCertDiffusionClient` receives the cert and calls `makePerasCertPoolWriterFromChainDB`.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally. [7](#0-6) 
6. `ChainDB.addPerasCertAsync` is called; `chainSelSync` processes the cert and calls `chainSelectionForBlock` for block `h`. [8](#0-7) 
7. Node A's chain selection now treats the fork containing `h` as having additional Peras weight and may switch to it, diverging from the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
