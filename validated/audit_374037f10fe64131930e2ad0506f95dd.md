### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Unauthorized Chain Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance for all block types contains a degenerate `validatePerasCert` implementation that unconditionally returns `Right` — accepting every certificate without any cryptographic or semantic check. An unprivileged peer can send a crafted `PerasCert` via the Peras certificate diffusion mini-protocol; the certificate is accepted, stored in `PerasCertDB`, and its boost is added to the shared `PerasWeightSnapshot`. Because `chainSelectionForBlock` reads that snapshot when comparing candidate chains, the injected boost can cause the node to prefer a fork it would not otherwise select.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The sole `BlockSupportsPeras` instance (the degenerate "compile-all-blocks" instance) implements `validatePerasCert` as:

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

No signature is checked, no committee eligibility is verified, no round-number rules are enforced. Every `PerasCert` from every peer is promoted to a `ValidatedPerasCert` carrying the full configured `perasWeight` boost. [1](#0-0) 

**Inbound path — `processCerts` calls the stub:**

`processCerts` in the Peras cert object-pool writer calls the injected `validateCert` function (which is `validatePerasCert mkPerasParams`) on every certificate received from a peer. Because the stub always returns `Right`, the `partitionEithers` branch that would throw `PerasCertInboundException` is never reached, and every certificate is timestamped and forwarded to `addCert`. [2](#0-1) 

**Chain-selection path — accepted certificate triggers `chainSelectionForBlock`:**

`chainSelSync` for `ChainSelAddPerasCert` adds the certificate to `PerasCertDB` and, if the boosted block is present in the VolatileDB, immediately calls `chainSelectionForBlock`. That function reads the live `PerasWeightSnapshot` — which now includes the injected boost — and uses it to compare the candidate fork against the current chain. [3](#0-2) 

**Shared resource — `PerasWeightSnapshot` used in chain selection:**

`chainSelectionForBlock` reads the weight snapshot atomically and passes it to `constructPreferableCandidates`. The snapshot maps block points to their cumulative boost; a fake certificate for a block on a fork inflates that fork's `wsvTotalWeight`, potentially making it heavier than the current chain. [4](#0-3) 

**Weight computation — `weightBoostOfFragment` sums all boosts from the snapshot:** [5](#0-4) 

**`PerasWeightSnapshot` built from all certs in `PerasCertDB` without chain-membership check:** [6](#0-5) 

---

### Impact Explanation

The `PerasWeightSnapshot` is a shared resource consumed by every chain-selection comparison. Because `validatePerasCert` performs no verification, any peer can inject a certificate that boosts an arbitrary block already present in the VolatileDB. If the boosted block is on a competing fork, that fork's `wsvTotalWeight` increases by `perasWeight` (a configurable parameter). A sufficiently large boost causes `preferAnchoredCandidate` to return `ShouldSwitch`, making the node adopt a fork it would not otherwise prefer — a chain-selection safety failure triggered by an unprivileged peer with no stake.

This is the direct analog to the Predy H-03 bug: in Predy, two pairs share the same Uniswap pool without per-pair liquidity accounting, so one pair's reallocation consumes the other's liquidity. Here, the `PerasWeightSnapshot` is the shared resource used across all chain comparisons, and the absence of certificate validation lets any peer inject weight into it on behalf of any fork, corrupting the accounting that chain selection relies on.

---

### Likelihood Explanation

The attack requires only:
1. A TCP connection to the target node (standard peer relationship).
2. Knowledge of a block hash present in the node's VolatileDB — trivially obtained via the ChainSync mini-protocol.
3. Sending a `PerasCert` with `pcCertBoostedBlock` set to a block on a competing fork via the Peras cert diffusion mini-protocol.

No stake, no keys, no privileged access are needed. The Peras cert diffusion code (`makePerasVotePoolWriterFromChainDB`, `addPerasCertAsync`) is compiled into the production binary and the `ChainDB` API exposes `addPerasCertAsync` as a first-class operation.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert`: verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the public keys of the declared committee members, and confirm each member's VRF-based eligibility proof for the given round.
2. **Implement real vote validation** in `validatePerasVote`: verify the individual BLS/VRF signature, not merely a stake-distribution lookup.
3. **Gate the cert diffusion mini-protocol** behind a feature flag that is disabled until the full validation logic is in place, so the stub cannot be reached from the network in any deployment.
4. **Add a chain-membership check** before accepting a certificate: the boosted block should be reachable from a known chain tip within the last `k` blocks, preventing boosts for arbitrary orphan blocks.

---

### Proof of Concept

```
1. Attacker connects to an honest node as a standard peer.

2. Via ChainSync, attacker learns block hash H at slot S on a competing fork
   that is currently in the node's VolatileDB but not on its selected chain.

3. Attacker crafts:
     cert = PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint S H }
   (no valid signature required — the stub ignores it).

4. Attacker sends cert via the Peras cert diffusion mini-protocol.

5. processCerts calls validatePerasCert, which returns Right unconditionally.

6. addPerasCertAsync enqueues ChainSelAddPerasCert.

7. chainSelSync finds H in the VolatileDB and calls chainSelectionForBlock.

8. chainSelectionForBlock reads the PerasWeightSnapshot, which now includes
   boost = perasWeight for block H.

9. constructPreferableCandidates computes wsvTotalWeight for the fork containing H.
   If perasWeight > (currentChainLength - forkLength), preferAnchoredCandidate
   returns ShouldSwitch and the node adopts the fork.

10. The node has switched to a non-canonical chain driven by a fake certificate.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L211-214)
```haskell
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```
