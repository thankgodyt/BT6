### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Adversarial Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing no cryptographic or structural validation. Because Peras certificates directly inflate the `wsvTotalWeight` used in chain selection (`preferCandidate`), an unprivileged peer can inject arbitrarily crafted certificates that boost any block point, causing an honest node to prefer a non-canonical adversarial chain.

---

### Finding Description

**Root cause — stub validator always succeeds:**

The `BlockSupportsPeras` instance in `SupportsPeras.hs` carries an explicit TODO and returns `Right` unconditionally:

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

**Inbound path — peer-supplied certificates reach the stub:**

`makePerasCertPoolWriterFromChainDB` in the object-diffusion layer calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. Every certificate received from a remote peer is passed through this stub:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` only rejects a batch when `validateCert` returns `Left`; since the stub never does, every peer-supplied certificate is accepted and timestamped: [3](#0-2) 

**Weight snapshot — accepted certificates inflate chain weight:**

`implGetWeightSnapshot` builds a `PerasWeightSnapshot` directly from every certificate stored in `PerasCertDB`, with no further validation gate:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [4](#0-3) 

**Chain selection — inflated weight drives fork preference:**

`weightedSelectView` computes `wsvWeightBoost` from the snapshot, and `preferCandidate` switches to a candidate chain whenever `wsvTotalWeight cand > wsvTotalWeight ours`:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
``` [5](#0-4) 

`chainSelSync` then triggers chain selection for the boosted block, potentially switching the node's selection to the adversarial fork: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that names any `Point blk` as the boosted block — including a block on an adversarial fork — and assign it the full `perasWeight` boost. Because `validatePerasCert` never rejects any certificate, the adversarial weight is added to the `PerasWeightSnapshot` and used verbatim in `preferCandidate`. If the adversarial chain's `wsvTotalWeight` (block number + injected boost) exceeds the honest chain's total weight, the node switches to the adversarial fork. This is a **chain selection error** that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

Any peer connected via the object-diffusion miniprotocol can send `PerasCert` messages. No stake, key material, or privileged access is required. The attacker only needs to construct a `PerasCert` with a `pcCertBoostedBlock` pointing to a block on their fork and a `pcCertRound` not already in the database. The stub validator guarantees acceptance. This is directly reachable from the network layer with a single crafted message.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's committee signature(s) against the active Peras committee derived from the ledger's stake distribution.
2. That the boosted block's slot falls within the valid range for the claimed round number.
3. That the quorum threshold is actually met by the certificate's aggregate stake proof.

Until real validation is in place, Peras weight boosts should not influence chain selection in any production-facing configuration.

---

### Proof of Concept

1. Connect to a target node as a peer via the object-diffusion miniprotocol.
2. Send a `PerasCert` with:
   - `pcCertRound` = any round not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the tip of an adversarial fork block already in the node's `VolatileDB`
3. `processCerts` calls `validatePerasCert mkPerasParams` → returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` unconditionally.
4. The cert is inserted into `PerasCertDB` via `addPerasCertAsync`.
5. `implGetWeightSnapshot` includes the adversarial block point with full `perasWeight` boost.
6. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block; `preferCandidate` computes `wsvTotalWeight` for the adversarial fragment as `blockNo + perasWeight`, which exceeds the honest chain's `blockNo + 0`.
7. The node switches its selection to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
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
