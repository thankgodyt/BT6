Now I have a complete picture of the full attack path. Let me compile the finding.

---

### Title
Degenerate `validatePerasCert` Wired into Production NodeToNode Allows Any Peer to Forge Peras Certificates and Manipulate Chain Selection — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance unconditionally returns `Right` from `validatePerasCert` for any certificate content. This instance is the **only** instance in the codebase (a global overlapping instance for all `StandardHash blk`) and is wired directly into the production NodeToNode ObjectDiffusion inbound handler. An unprivileged peer can send a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block in the node's VolatileDB, bypass all certificate validation, have the forged certificate stored in the `PerasCertDB`, and trigger chain selection with a `PerasWeight 15` boost applied to the targeted block — potentially causing the node to switch to a minority fork.

### Finding Description

**Step 1 — Degenerate validation (always `Right`):** [1](#0-0) 

The `validatePerasCert` implementation is a TODO stub that returns `Right` for every certificate, regardless of round number, boosted block hash, committee membership, or cryptographic signatures.

**Step 2 — Wired into production NodeToNode:** [2](#0-1) 

`hPerasCertDiffusionClient` uses `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. This is not test code — it is the production NodeToNode handler.

**Step 3 — `processCerts` passes any cert through:** [3](#0-2) 

Since `validatePerasCert` always returns `Right`, `processCerts` always takes the `([], validatedCerts)` branch and calls `ChainDB.addPerasCertAsync` with the forged cert.

**Step 4 — `chainSelSync` stores the cert and triggers chain selection:** [4](#0-3) 

The cert is added to `PerasCertDB`. If the boosted block is in the VolatileDB (i.e., a valid block already received via BlockFetch), `chainSelectionForBlock` is called for that block.

**Step 5 — Weight snapshot includes the forged boost:** [5](#0-4) 

`implGetWeightSnapshot` computes the `PerasWeightSnapshot` from all certs in the DB, including the forged one. The boost value is `perasWeight mkPerasParams = PerasWeight 15`. [6](#0-5) 

**Step 6 — Chain selection uses the inflated weight:** [7](#0-6) 

`chainSelectionForBlock` reads the current `PerasWeightSnapshot` (now containing the forged boost), constructs candidate fragments, and calls `preferAnchoredCandidate` with Peras weights. If the minority fork's total weight (block count + 15) exceeds the current chain's weight, the node switches. [8](#0-7) 

### Impact Explanation

A single unprivileged NodeToNode peer can:
1. Identify a valid block in the node's VolatileDB that is on a minority fork (e.g., via ChainSync).
2. Send a `PerasCert` with `pcCertBoostedBlock` set to that block's point and any `pcCertRound`.
3. The node stores the cert, applies a `PerasWeight 15` boost to the minority fork, and switches to it if the fork is within 15 blocks of the current tip.
4. Once the node switches and the minority fork advances past the immutability threshold, the switch becomes irreversible — constituting an irreversible divergent chain.

The Peras boost of 15 is equivalent to 15 blocks of chain weight, which is a substantial advantage. On a live network where forks of 1–3 blocks are common, this is sufficient to cause a chain switch in most realistic scenarios.

### Likelihood Explanation

- The ObjectDiffusion protocol is fully wired into production NodeToNode code.
- The degenerate instance is the **only** `BlockSupportsPeras` instance (global for all `StandardHash blk`); there is no per-block-type override.
- The attacker needs only to know a block hash in the VolatileDB on a minority fork, which is observable via ChainSync.
- No stake, keys, or privileged access are required.
- The only natural mitigations are: (a) the boosted block must already be in the VolatileDB, and (b) the PerasCertDB deduplicates by round number (one forged cert per round). However, an attacker can send one forged cert per Peras round (every 90 slots), each boosting a different block.

### Recommendation

1. **Immediate**: Gate the ObjectDiffusion PerasCert inbound handler behind a feature flag or network protocol version check so it is not active until real `validatePerasCert` is implemented.
2. **Short-term**: Replace the degenerate `validatePerasCert` stub with a real implementation that verifies committee membership, quorum, and cryptographic signatures before merging the Peras diffusion code into any release branch.
3. **Defense-in-depth**: Add a guard in `chainSelSync` that rejects certificates whose `pcCertBoostedBlock` is not on any known candidate chain, independent of `validatePerasCert`.

### Proof of Concept

```haskell
-- In an io-sim or local testnet test:
-- 1. Set up a node with a VolatileDB containing a minority-fork block B_fork
--    at point p_fork, where the current chain is only 5 blocks ahead.
-- 2. Connect as an unprivileged NodeToNode peer.
-- 3. Send via ObjectDiffusion:
let forgedCert = PerasCert
      { pcCertRound      = PerasRoundNo 42   -- arbitrary round
      , pcCertBoostedBlock = p_fork           -- point of minority-fork block
      }
-- 4. processCerts calls validatePerasCert which returns Right unconditionally.
-- 5. addPerasCertAsync enqueues the cert.
-- 6. chainSelSync finds B_fork in VolatileDB, applies PerasWeight 15 boost.
-- 7. preferAnchoredCandidate: minority fork weight = (tip_fork_blockno + 15)
--    vs current chain weight = (tip_current_blockno + 0).
--    If tip_fork_blockno + 15 > tip_current_blockno, node switches to fork.
-- Assert: node's current chain tip is now on the minority fork.
```

The unit test described in the question (sending a `PerasCert` with a fabricated boosted block hash through `processCerts` and asserting it is rejected before reaching `addPerasCertAsync`) would **fail** on unmodified code, confirming the vulnerability.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-686)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

  -- The current chain we're working with here is not longer than @k@ blocks
  -- (see 'getCurrentChain' and 'cdbChain'), which is easier to reason about
  -- when doing chain selection, etc.
  assert (fromIntegral (AF.length curChain) <= unNonZero k) pure ()

  let
    immBlockNo :: WithOrigin BlockNo
    immBlockNo = AF.anchorBlockNo curChain

  if
    -- The chain might have grown since we added the block such that the
    -- block is older than the immutable tip.
    | olderThanImmTip hdr immBlockNo -> do
        traceWith addBlockTracer $ IgnoreBlockOlderThanImmTip p

    -- The block is invalid
    | Just (InvalidBlockInfo reason _) <- Map.lookup (headerHash hdr) invalid -> do
        traceWith addBlockTracer $ IgnoreInvalidBlock p reason

        -- We wouldn't know the block is invalid if its prefix was invalid,
        -- hence 'InvalidBlockPunishment.BlockItself'.
        InvalidBlockPunishment.enact
          punish
          InvalidBlockPunishment.BlockItself

    -- Try to select a chain involving the block.
    | otherwise -> do
        -- Construct all 'ChainDiff's involving the block.
        chainDiffs <-
          constructPreferableCandidates
            cdb
            weights
            curChain
            (Map.singleton (headerHash hdr) hdr)
            (headerRealPoint hdr)

        let traceNoChange = traceWith addBlockTracer $ StoreButDontChange p

            chainSelEnv = mkChainSelEnv cdb blockCache weights curChain (Just (p, punish))

        case NE.nonEmpty chainDiffs of
          Just chainDiffs' -> do
            -- Find the best valid candidate and, if valid, perform a
            -- switch. Log if none were found.
            flip whenNothing traceNoChange
              =<< chainSelection
                chainSelEnv
                chainDiffs'
                (switchTo cdb weights (Just p))
          -- No candidate better than our chain.
          Nothing -> traceNoChange
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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
