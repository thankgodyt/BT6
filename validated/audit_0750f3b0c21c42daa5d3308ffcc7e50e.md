### Title
Unconditional Peras Certificate Acceptance Bypasses Vote Verification, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted target; the certificate passes validation, is stored in the `PerasCertDB`, and immediately triggers chain selection for the boosted block. This is the direct analog of the external report's desync: in Velodrome, a voter receives a bribe (reward) based on a snapshot taken at `EPOCH_END - 1` but can redirect their vote weight before distribution, obtaining the reward without the corresponding obligation. Here, a certificate obtains the chain-selection boost (the "reward") without the obligation of having been formed from a quorum of legitimate committee votes.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase — a blanket degenerate instance over all `StandardHash blk` types, explicitly noted as a placeholder: [2](#0-1) 

**Production inbound path — `processCerts` calls `validatePerasCert`:** [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as the validation function for every certificate received from a peer. Because `validatePerasCert` always returns `Right`, `processCerts` accepts every certificate unconditionally: [4](#0-3) 

**Chain selection is triggered for the boosted block:**

After acceptance, the certificate is enqueued via `addPerasCertAsync`: [5](#0-4) 

`chainSelSync` then processes the certificate, looks up the boosted block in the `VolatileDB`, and calls `chainSelectionForBlock` for it: [6](#0-5) 

The `PerasWeightSnapshot` used during chain selection is built directly from the accepted certificates: [7](#0-6) 

**Analog mapping to the external report:**

| Velodrome | Ouroboros Consensus |
|---|---|
| Bribe reward paid based on `EPOCH_END - 1` snapshot | Certificate boost applied based on `validatePerasCert` result |
| Distribution (`Voter.distribute`) happens at `EPOCH_END + X` | Chain selection (`chainSelectionForBlock`) happens after cert is queued |
| Voter changes vote between snapshot and distribution | Attacker sends crafted cert with no valid votes behind it |
| Voter receives bribe without vote weight influencing emissions | Certificate boosts a block without a quorum of legitimate committee votes |

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` naming any block in the `VolatileDB` as the boosted target. The certificate is accepted unconditionally, stored, and triggers chain selection. The `PerasWeightSnapshot` now assigns `perasWeight` to that block. If the attacker's chosen block is on a fork, the additional weight can tip chain selection in favour of that fork, causing the honest node to switch away from the canonical chain. This satisfies the **High** impact criterion: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

The attack requires only a network connection to the target node and the ability to send a well-formed (but content-arbitrary) `PerasCert` message over the Peras certificate diffusion mini-protocol. No key material, stake, or operator access is needed. The `processCerts` function disconnects the peer only if `validatePerasCert` returns `Left`, which it never does. Likelihood is **High**.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion mini-protocol is enabled in production. At minimum, validation must verify:

1. The certificate's `pcCertRound` falls within the acceptable window relative to the current chain tip.
2. The certificate is backed by a quorum of cryptographically signed votes from the committee elected for that round, using the stake distribution snapshot fixed at the start of the round (not the live distribution).
3. Each vote's VRF proof confirms the voter was legitimately elected to the committee for that round.
4. The `pcCertBoostedBlock` is a known, valid block on a chain that could plausibly be adopted.

Until this is implemented, the Peras certificate diffusion mini-protocol should not be exposed to untrusted peers.

---

### Proof of Concept

1. Establish a peer connection to the target node.
2. Identify a block hash `H` in the node's `VolatileDB` that is on a fork the attacker wishes to promote.
3. Construct a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slot H }` for any round `R`.
4. Send the certificate via the Peras certificate diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. The certificate is enqueued via `addPerasCertAsync` → `ChainSelAddPerasCert`.
7. `chainSelSync` retrieves block `H` from the `VolatileDB` and calls `chainSelectionForBlock` with the boosted weight.
8. If `H`'s chain now has greater total weight than the current selection, the node switches to the attacker's fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-311)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```
