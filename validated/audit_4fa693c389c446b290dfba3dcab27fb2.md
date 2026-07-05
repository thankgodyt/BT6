### Title
`checkPreferTheirsOverOurs` Uses Incomplete Chain-Weight State (`emptyPerasWeightSnapshot`), Causing Wrong Peer-Disconnect Decisions Under Peras — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client is a gating function that decides whether to disconnect from a peer when a received header is beyond the forecast horizon. It calls `preferAnchoredCandidate` with a hardcoded `emptyPerasWeightSnapshot`, completely ignoring all Peras certificate weight boosts. This is the direct analog of the reported bug: a gating/validation function uses an incomplete view of the current state (ignoring pending/accumulated weight from certificates), producing wrong accept/reject decisions.

---

### Finding Description

When the ChainSync client receives a header whose slot is beyond the current forecast horizon, it cannot yet validate the header. It calls `checkPreferTheirsOverOurs` to decide whether to wait (if the candidate chain is better than ours) or disconnect (`CandidateTooSparse`) if the candidate is not worth waiting for.

The function is:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always zero Peras weight
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` accepts a `PerasWeightSnapshot blk` that encodes the Peras certificate weight boosts for blocks on the volatile chain. When this snapshot is non-empty, chain comparison uses total weight (block count + certificate boosts). When it is `emptyPerasWeightSnapshot`, comparison degrades to pure block-count comparison. [2](#0-1) 

The actual Peras weight snapshot is maintained in `cdbPerasCertDB` and is available via `getPerasWeightSnapshot`: [3](#0-2) 

The `PerasWeightSnapshot` is populated whenever a Peras certificate is added via `addPerasCertAsync`, which triggers chain selection for the boosted block: [4](#0-3) 

The `emptyPerasWeightSnapshot` constant is always zero: [5](#0-4) 

The code itself acknowledges the problem with a `TODO` referencing issue #64, but the fix has not been applied.

---

### Impact Explanation

**High — Chain selection error that causes an honest node to prefer a non-canonical, less-secure chain.**

Under Peras, the canonical chain is the one with the highest total weight (block count + certificate boosts), not simply the longest by block count. Two concrete failure modes arise from the incomplete state:

**Mode 1 — False disconnect (security-critical):**
- A peer offers a candidate chain that has *fewer blocks* than our chain but is *heavier* due to Peras certificate boosts (i.e., it is the canonical chain).
- The header is beyond the forecast horizon, so `checkPreferTheirsOverOurs` is invoked.
- With `emptyPerasWeightSnapshot`, `preferAnchoredCandidate` sees only block counts: their chain is shorter → `ShouldNotSwitch` → the node throws `CandidateTooSparse` and disconnects.
- With the actual weight snapshot, their chain is heavier → `ShouldSwitch` → the node should wait.
- **Result**: The node disconnects from the peer offering the canonical Peras-boosted chain and fails to adopt it, remaining on a less-secure chain. If this peer is the only or primary source of the canonical chain, the node is permanently stuck on the wrong fork.

**Mode 2 — False non-disconnect (resource waste, not security-critical):**
- A peer offers a chain that is longer by block count but lighter than our chain (our chain has Peras boosts).
- The node does not disconnect, wasting BlockFetch resources.

Mode 1 directly matches the allowed impact scope: "Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

---

### Likelihood Explanation

**Medium.** The conditions required are:

1. Peras is active and certificates have been issued (boosting blocks on a candidate chain).
2. A peer's candidate chain has Peras boosts but fewer blocks than the local chain at the time of the check.
3. The candidate header is beyond the forecast horizon (a normal occurrence during initial sync or when a peer is ahead).

Conditions 1 and 3 are routine during normal Peras operation. Condition 2 arises naturally when a fork has accumulated certificates but not yet extended its block count past the local tip. No adversarial capability is required — this can be triggered by any honest peer in a normal Peras-active network.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the actual `PerasWeightSnapshot` read atomically from `cdbPerasCertDB` (via `getPerasWeightSnapshot`). Since `checkPreferTheirsOverOurs` already runs inside an `STM` transaction (`atomically`), reading the snapshot is composable without additional locking. The existing `TODO` comment references issue #64 which proposes removing the check entirely; until that is done, the snapshot must be accurate.

---

### Proof of Concept

**Setup (private testnet or IOSim simulation):**

1. Start a node with Peras active. Let it build a local chain of N blocks with no certificates (weight = N).
2. Introduce a peer whose candidate chain has N−1 blocks but one Peras certificate boosting a block on that chain, giving it total weight N−1 + B where B > 1 (so the candidate is heavier).
3. Arrange for the candidate's tip header to be beyond the local forecast horizon (e.g., by having a large slot gap in the candidate chain).
4. Observe that `checkPreferTheirsOverOurs` is invoked. With `emptyPerasWeightSnapshot`, `preferAnchoredCandidate` compares block counts: N−1 < N → `ShouldNotSwitch` → `CandidateTooSparse` is thrown and the peer is disconnected.
5. Confirm that with the actual weight snapshot, the comparison would be N−1+B > N → `ShouldSwitch` → the node should wait and eventually adopt the heavier chain.

The node remains on the lighter chain, violating the Peras chain selection rule. [1](#0-0) [6](#0-5) [7](#0-6) [8](#0-7) [3](#0-2)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1834-1857)
```haskell
  checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
  checkPreferTheirsOverOurs kis
    | -- Precondition is fulfilled as ourFrag and theirFrag intersect by
      -- construction.
      shouldSwitch $
        preferAnchoredCandidate
          (configBlock cfg)
          -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
          emptyPerasWeightSnapshot
          ourFrag
          theirFrag =
        pure ()
    | otherwise =
        throwSTM $
          CandidateTooSparse
            mostRecentIntersection
            (ourTipFromChain ourFrag)
            (theirTipFromChain theirFrag)
   where
    KnownIntersectionState
      { mostRecentIntersection
      , ourFrag
      , theirFrag
      } = kis
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L167-213)
```haskell
preferAnchoredCandidate ::
  forall blk h h'.
  ( BlockSupportsProtocol blk
  , HasCallStack
  , GetHeader1 h
  , GetHeader1 h'
  , HeaderHash (h blk) ~ HeaderHash blk
  , HeaderHash (h blk) ~ HeaderHash (h' blk)
  , HasHeader (h blk)
  , HasHeader (h' blk)
  ) =>
  BlockConfig blk ->
  -- | Peras weights used to judge this chain.
  PerasWeightSnapshot blk ->
  -- | Our chain
  AnchoredFragment (h blk) ->
  -- | Candidate
  AnchoredFragment (h' blk) ->
  ShouldSwitch (ReasonForSwitch' blk)
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L344-346)
```haskell
getPerasWeightSnapshot ::
  ChainDbEnv m blk -> STM m (WithFingerprint (PerasWeightSnapshot blk))
getPerasWeightSnapshot CDB{..} = PerasCertDB.getWeightSnapshot cdbPerasCertDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L44-57)
```haskell
-- | Data structure for tracking the weight of blocks due to Peras boosts.
newtype PerasWeightSnapshot blk = PerasWeightSnapshot
  { getPerasWeightSnapshot :: Map (Point blk) PerasWeight
  }
  deriving stock Eq
  deriving Generic
  deriving newtype NoThunks

instance StandardHash blk => Show (PerasWeightSnapshot blk) where
  show = show . perasWeightSnapshotToList

-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```
