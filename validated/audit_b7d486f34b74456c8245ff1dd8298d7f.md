### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inject Arbitrary Weight Boosts into Chain Selection - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` — accepting every certificate as valid regardless of its cryptographic content, committee membership, or round correctness. Because `processCerts` in the Peras certificate object-pool writer calls this stub before adding certificates to the `PerasCertDB`, any unprivileged peer can inject arbitrary `PerasCert` objects that are stored with full weight boosts and immediately used to influence chain selection. This is the direct analog of the external report's pattern: internal accounting state (the weight snapshot) is updated based on a "validation" step that never actually validates, before the operation that should justify the state change (real cryptographic/committee verification) has occurred.

---

### Finding Description

**Root cause — stub validation always succeeds:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase (the comment explicitly calls it "degenerate instance for all blks to get things to compile"). It is not confined to tests; it is the production instance used for all block types.

**Inbound certificate processing uses this stub:** [2](#0-1) 

`processCerts` calls `validateCert` (bound to `validatePerasCert mkPerasParams`) on every inbound certificate. Because the stub always returns `Right`, the `(errs, _)` rejection branch is structurally unreachable. Every certificate in every batch passes "validation" and is forwarded to `addCert`.

**Certificate is committed to the DB before chain selection validates the boosted block:** [3](#0-2) 

In `chainSelSync` for `ChainSelAddPerasCert`:
1. Line 495: `PerasCertDB.addCert` is called — the certificate is written to the in-memory index and the weight snapshot is updated atomically.
2. Line 531: `chainSelectionForBlock` is called — only now does the node attempt to validate the boosted block via the ledger.

This is the ordering analog of the external report: the accounting state (weight boost in `PerasCertDB`) is committed **before** the operation that should justify it (ledger validation of the boosted block) completes. The weight snapshot returned by `getWeightSnapshot` already reflects the fraudulent boost at the moment chain selection runs.

**Weight snapshot feeds directly into chain comparison:** [4](#0-3) 

`implGetWeightSnapshot` iterates over all certificates in `pcdsCertsByTicket` — including those added via the stub — and constructs the `PerasWeightSnapshot` used by `preferAnchoredCandidate` during chain selection.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that boosts any block hash it chooses. Because `validatePerasCert` is a no-op, the certificate passes inbound processing, is stored in `PerasCertDB`, and its weight boost is immediately reflected in the `PerasWeightSnapshot`. Chain selection then uses this snapshot when comparing candidate fragments via `preferAnchoredCandidate`. A fork that would otherwise lose on block number or VRF tiebreaker can be made to appear heavier than the honest chain, causing the node to switch to it. This constitutes a **chain selection manipulation** — an honest node can be made to prefer a non-canonical or adversarially-controlled fork without the attacker needing any stake, keys, or operator access.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is a public peer-to-peer channel. Any connected peer can submit a `PerasCert` message. No authentication, stake ownership, or committee membership is checked before the certificate is accepted. The attack requires only a network connection to a node with Peras enabled. The CHANGELOG notes Peras is disabled by default, but the vulnerability is fully present and exploitable in any deployment where it is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's committee signatures against the registered committee keys for the claimed round.
- That the claimed round number is within the valid range relative to the current chain tip.
- That the boosted block hash corresponds to a block that was actually a valid candidate in that round.

Until real validation is in place, inbound Peras certificates from untrusted peers should be rejected entirely (or the Peras object-diffusion server should not be exposed). The ordering issue in `chainSelSync` should also be addressed by validating the boosted block's existence and header validity **before** committing the certificate to `PerasCertDB`.

---

### Proof of Concept

1. Connect to a Cardano node with Peras enabled as an unprivileged peer via the node-to-node mini-protocol.
2. Craft a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of a block on a competing fork>`.
3. Send the certificate via the Peras object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..}` unconditionally.
5. The certificate is forwarded to `ChainDB.addPerasCertAsync`, enqueued as `ChainSelAddPerasCert`, and processed by `chainSelSync`.
6. `PerasCertDB.addCert` commits the certificate; `implGetWeightSnapshot` now returns a snapshot that includes the fraudulent boost.
7. `chainSelectionForBlock` runs with the boosted weight snapshot; `preferAnchoredCandidate` compares the competing fork (now artificially heavier) against the current chain and may switch to it. [5](#0-4) [6](#0-5) [7](#0-6)

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
