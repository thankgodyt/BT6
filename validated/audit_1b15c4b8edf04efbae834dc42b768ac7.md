### Title
`validatePerasCert` Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized `PerasWeightSnapshot` Manipulation and Chain-Selection Bypass — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This stub is wired directly into the production Peras-certificate inbound miniprotocol handler (`hPerasCertDiffusionClient`). An unprivileged peer can send a crafted `PerasCert` naming any block point as the boosted target; the certificate passes "validation", is inserted into the `PerasCertDB`, and inflates the `PerasWeightSnapshot` entry for that block. Chain selection then uses the inflated weight to prefer the adversarial fork over the canonical chain, causing the honest node to roll back and adopt a non-canonical chain without any operator fault.

---

### Finding Description

**Root cause — stub validation always succeeds**

`validatePerasCert` in the default `BlockSupportsPeras` instance:

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

Every `PerasCert` value, regardless of its contents, is wrapped in `Right ValidatedPerasCert` and assigned the full `perasWeight` boost. No aggregate-signature check, no committee-membership check, no round-number sanity check is performed.

**Wiring into the production inbound handler**

`makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` is the writer used by the production `hPerasCertDiffusionClient` handler:

```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            ...
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [3](#0-2) 

**`processCerts` accepts the always-`Right` result and inserts the cert**

```haskell
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` never produces a `Left`, the `(errs, _)` branch is unreachable. Every certificate from every peer is accepted.

**`PerasWeightSnapshot` is the registry that chain selection reads**

`implGetWeightSnapshot` builds the snapshot directly from every cert in the DB:

```haskell
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
``` [5](#0-4) 

Chain selection reads this snapshot atomically and uses it in every candidate comparison:

```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [6](#0-5) 

`totalWeightOfFragment` computes `blockNo + weightBoost`; a sufficiently large injected boost makes a shorter adversarial fork outweigh the canonical chain:

```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
``` [7](#0-6) 

**Exploit path (end-to-end)**

1. Attacker connects to the target node as a normal peer.
2. Attacker sends a crafted `PerasCert{pcCertRound = r, pcCertBoostedBlock = adversarialPoint}` via the `PerasCertDiffusion` miniprotocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. `ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` processes it via `chainSelSync cdb (ChainSelAddPerasCert cert ...)`.
5. `PerasCertDB.addCert` inserts the cert; `getWeightSnapshot` now returns a non-zero boost for `adversarialPoint`.
6. `chainSelectionForBlock` is triggered for the boosted block; `constructPreferableCandidates` finds the adversarial fork now preferred.
7. The node rolls back and adopts the adversarial chain. [8](#0-7) 

---

### Impact Explanation

**High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

The `PerasWeightSnapshot` is the consensus-critical registry that determines which fork wins chain selection when Peras is active. Because the registry is updated from peer-supplied data that is never cryptographically verified, any peer can inject an arbitrary weight boost for any block point. A single crafted certificate whose `perasWeight` exceeds the block-number difference between the canonical tip and an adversarial fork tip is sufficient to flip chain selection. The node will roll back up to `k` blocks and adopt the adversarial chain, violating the chain-growth and common-prefix properties that Ouroboros safety depends on.

---

### Likelihood Explanation

**Medium.** The `PerasCertDiffusion` miniprotocol handler is registered unconditionally in `NodeToNode.hs`. The stub `validatePerasCert` is the only implementation present for all block types. The attack requires Peras to be enabled (currently non-default), but the vulnerable code path is always compiled in and active whenever the miniprotocol is negotiated. No stake, no keys, and no privileged access are required — only a standard peer connection.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the certificate's aggregate BLS signature against the committee's public keys and the epoch stake distribution before accepting it.
2. Until real validation is in place, gate the `PerasCertDiffusion` miniprotocol behind a feature flag that is off by default and cannot be enabled without a matching real `validatePerasCert` implementation.
3. Consider adding a `PerasCertDB.addCert` guard that re-checks the `ValidatedPerasCert` invariant (e.g., a non-forgeable witness type) so that the DB itself cannot be populated with unvalidated data even if the inbound handler is bypassed.

---

### Proof of Concept

**Private-testnet reproduction (no privileged access required):**

```
1. Start a local Cardano node with Peras enabled.

2. Connect a custom peer that speaks the PerasCertDiffusion miniprotocol.

3. Build a PerasCert CBOR payload:
     pcCertRound      = <any round not yet in the DB>
     pcCertBoostedBlock = <SlotNo, Hash of a block on a shorter fork>

4. Send the payload via the ObjectDiffusion inbound protocol.

5. Observe via tracing:
     - "ChainSelectionForBoostedBlock" trace fires for the adversarial block.
     - Chain selection switches to the shorter fork.
     - The node rolls back previously-adopted blocks.

Root cause confirmed: processCerts → validatePerasCert mkPerasParams → always Right
→ addPerasCertAsync → chainSelSync → PerasWeightSnapshot updated
→ preferAnchoredCandidate flips → fork switch.
``` [1](#0-0) [9](#0-8) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L313-317)
```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
