### Title
Unconditional `validatePerasCert` Acceptance Allows Unprivileged Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or semantic checks. This stub is wired directly into the live `perasCertDiffusion` miniprotocol handler. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted-block hash; the node will accept it, store it in the `PerasCertDB`, and trigger chain selection with the fake boost weight, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify an inbound Peras certificate before it is stored and acted upon. The only production instance of this typeclass is the degenerate catch-all instance at line 320 of `SupportsPeras.hs`:

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

This stub is not isolated to tests. It is the validator passed directly into `processCerts` in the production pool-writer constructors:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate not already in the DB. Because `validateCert` is `validatePerasCert mkPerasParams`, which always returns `Right`, every certificate passes:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)   -- ← never reached
``` [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` is wired into the live `hPerasCertDiffusionClient` handler in the node-to-node application:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

Once a certificate is accepted and stored, `chainSelSync` in `ChainSel.hs` uses it to trigger chain selection for the boosted block, applying the fake boost weight to the chain-weight comparison: [5](#0-4) 

The `PerasWeightSnapshot` used during chain selection sums all boost weights for blocks on a fragment, so a fake certificate with a large `perasWeight` can make an otherwise-shorter or weaker chain appear heavier: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `PerasRoundNo` and any `Point blk` (block hash) as the boosted block. Because `validatePerasCert` performs no BLS aggregate-signature check, no committee-membership check, no round-eligibility check, and no quorum check, the certificate is unconditionally stored and its boost weight is applied to chain selection. The attacker can:

1. Boost a block on a minority fork, causing the victim node to switch away from the honest majority chain (chain-selection safety failure).
2. Boost a block that has not yet been received, pre-loading a fake weight that will be applied the moment that block arrives.
3. Inject certificates for past rounds to retroactively alter the weight of already-immutable-looking chain segments.

This directly matches the **Critical** and **High** impact categories: bypass of certificate validation enabling unauthorized certificate acceptance, and a chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

The `perasCertDiffusion` miniprotocol is enabled for every node-to-node connection (both initiator-only and initiator-and-responder modes). Any peer that can establish a connection — including a completely unprivileged external node — can send a batch of crafted certificates. The attack requires no keys, no stake, and no prior knowledge beyond the target node's address. The only natural barrier is the per-round deduplication check (`Set.member roundNo alreadyInDb`), which an attacker trivially bypasses by using a fresh round number for each injection.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` before the Peras certificate diffusion miniprotocol is enabled in production. At minimum, verify the aggregate BLS signature against the claimed voter set and the `(roundNo, boostedBlock)` message, as the `EveryoneVotes` committee implementation already does in `implVerifyCert`.
2. **Gate the miniprotocol** behind a feature flag that is disabled until validation is complete, preventing the stub from being reachable on a live network.
3. **Add a round-range check** so that certificates for rounds far in the past or future are rejected before any storage or chain-selection side-effects occur.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a victim node via the standard node-to-node protocol.
2. Attacker's `perasCertDiffusion` outbound peer sends a `PerasCert` with:
   - `pcCertRound = <any fresh round number>`
   - `pcCertBoostedBlock = <hash of a block on attacker's preferred fork>`
3. Victim's `objectDiffusionInbound` handler calls `opwAddObjects` on `makePerasCertPoolWriterFromChainDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The certificate is stored via `ChainDB.addPerasCertAsync`.
6. `chainSelSync` fires for the boosted block; `weightBoostOfFragment` adds `perasWeight` to the attacker's fork weight.
7. If the boosted fork's total weight now exceeds the current selection's weight, the victim switches chains.

**Root cause line:**

```haskell
validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [7](#0-6) 

No cryptographic material in `cert` is ever inspected; the function is a pure identity wrapper that stamps every input as valid.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
