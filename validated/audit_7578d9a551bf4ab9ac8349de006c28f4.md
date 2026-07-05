### Title
Unconditional `validatePerasCert` Acceptance Bypasses Peras Certificate Validation, Enabling Fraudulent Chain-Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance ships a deliberately stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Both production pool-writer paths (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) call this stub directly. An unprivileged peer can therefore inject any crafted `PerasCert` — with an arbitrary round number and an arbitrary boosted-block point — and the node will accept it, store it in the `PerasCertDB`, and immediately re-run chain selection with the fraudulent boost weight applied. This is the direct analog of the uninitialized `feeRecipient`: a critical field (the validation logic) was never implemented, leaving the system operating on a wrong/null default.

---

### Finding Description

**Root cause — stub validation always returns `Right`:** [1](#0-0) 

The comment on line 318 explicitly marks this as a "degenerate instance … to get things to compile." The `validatePerasCert` method ignores every field of the certificate and returns a `ValidatedPerasCert` carrying whatever `perasWeight params` says, with no signature check, no committee-membership check, no round-number sanity check, and no boosted-block existence check.

**Production pool writers call this stub directly:**

Both `makePerasCertPoolWriterFromCertDB` (line 103) and `makePerasCertPoolWriterFromChainDB` (line 126) pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and only rejects a batch when at least one call returns `Left`. Because the stub always returns `Right`, no certificate is ever rejected: [3](#0-2) 

**Accepted certificates immediately trigger chain selection:**

Once a certificate passes the (absent) validation gate and is stored in the `PerasCertDB`, `chainSelSync` in `ChainSel.hs` re-runs chain selection for the boosted block, applying the fraudulent weight: [4](#0-3) 

The weight boost is then used by `weightBoostOfFragment` / `totalWeightOfFragment` to compare candidate chains, so a fraudulently boosted fork can win chain selection over the honest canonical chain: [5](#0-4) 

---

### Impact Explanation

When Peras is enabled via `rnFeatureFlags`, an unprivileged peer can:

1. Craft a `PerasCert` naming any block point as `pcCertBoostedBlock` and any `PerasRoundNo`.
2. Send it over the Peras-certificate ObjectDiffusion mini-protocol.
3. The receiving node accepts it unconditionally, stores it, and re-runs chain selection.
4. The fraudulent boost (`perasWeight = 15` by default from `mkPerasParams`) is added to the targeted fork's weight.
5. If the targeted fork's total weight now exceeds the honest chain's weight, the node switches to the adversarial fork — a chain-selection safety failure.

This satisfies the **High** impact criterion: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."* It also satisfies the **Critical** criterion: *"Bypass of … certificate … validation … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

Peras is currently an opt-in experimental feature (`rnFeatureFlags`), disabled by default. Any operator or testnet that enables it is immediately exposed. The attack requires only a network connection to the target node and knowledge of a block hash on a competing fork — no keys, no stake, no privileged access. The entry path (ObjectDiffusion mini-protocol) is reachable from any peer the node connects to.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's cryptographic signature against the claimed committee members.
- That the signer(s) are eligible committee members for the stated round (VRF-based committee selection).
- That the aggregate stake of the signers meets the quorum threshold (`perasQuorumStakeThreshold`).
- That `pcCertBoostedBlock` refers to a block that satisfies `perasBlockMinSlots` age and `perasCertMaxRounds` freshness constraints.

Until a real implementation is available, the pool writers should refuse to accept any inbound certificate (return a hard error or drop silently) rather than accept all of them. The `TODO` at issue [#120](https://github.com/tweag/cardano-peras/issues/120) must be resolved before Peras is enabled on any network where adversarial peers are possible.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Adversarial peer
  → ObjectDiffusion mini-protocol (PerasCert channel)
  → makePerasCertPoolWriterFromChainDB.opwAddObjects [craftedCert]
  → processCerts … (validatePerasCert mkPerasParams) …
      validatePerasCert _ craftedCert
        = Right (ValidatedPerasCert { vpcCert = craftedCert
                                    , vpcCertBoost = PerasWeight 15 })
      -- always Right, no check performed
  → ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
  → chainSelSync … (ChainSelAddPerasCert cert varProcessed)
  → chainSelectionForBlock … boostedHdr   -- re-runs chain selection
  → totalWeightOfFragment now includes +15 for the adversary's fork
  → node may switch to adversarial chain
```

The stub is at: [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-268)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)

```
