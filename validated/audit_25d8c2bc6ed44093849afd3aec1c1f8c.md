### Title
Chain Selection Bypass via Empty Peras Weight Snapshot in `checkPreferTheirsOverOurs` - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client unconditionally uses `emptyPerasWeightSnapshot` (a hardcoded zero-weight state) instead of the live `PerasWeightSnapshot` from the `PerasCertDB` when deciding whether to disconnect from a peer whose headers exceed the forecast horizon. This is the direct analog of the RedStone oracle bug: a query/comparison function uses stale/empty cached state instead of the current state, causing incorrect decisions.

---

### Finding Description

When a peer sends a header whose slot is beyond the current forecast horizon, the ChainSync client cannot yet obtain a `LedgerView` for that slot. It must decide whether to wait (if the peer's chain is still preferable) or disconnect (if it is not). This decision is made in `checkPreferTheirsOverOurs`:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- <-- always zero, ignores all Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

The function is called from `readLedgerStateHelper` whenever `prj lst` returns `Nothing` (forecast horizon exceeded) and the STM transaction must decide whether to `retry` or `throwSTM`: [2](#0-1) 

The real Peras weight snapshot is available via `getPerasWeightSnapshot` on the `ChainDB` API: [3](#0-2) 

And it is correctly used in every other chain-comparison site — for example, in `BlockFetch.ClientInterface`: [4](#0-3) 

And in the `NodeKernel` GSM view: [5](#0-4) 

`preferAnchoredCandidate` with a non-empty snapshot computes total weight as `blockNo + weightBoost`; with `emptyPerasWeightSnapshot` it degenerates to a pure block-count comparison: [6](#0-5) 

The `PerasWeightSnapshot` type and `emptyPerasWeightSnapshot` constant: [7](#0-6) 

---

### Impact Explanation

When Peras is active and certificates have been issued boosting blocks on a peer's chain:

1. The peer's candidate chain may have **fewer blocks** than the node's current chain but **greater total Peras weight** (block count + certificate boosts).
2. If that chain also contains a slot gap larger than the forecast window, `checkPreferTheirsOverOurs` is triggered.
3. Because `emptyPerasWeightSnapshot` is used, the comparison ignores all Peras boosts and evaluates the candidate as lighter (fewer blocks).
4. The node throws `CandidateTooSparse` and **disconnects from the honest peer**.
5. The node remains on a chain that is lighter by Peras weight — i.e., the **non-canonical chain under Peras rules**.

This is a **High** chain-selection bug: an unprivileged peer serving the Peras-canonical chain can be incorrectly rejected, causing the honest node to prefer a less-secure, non-canonical chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

- Peras is implemented and integrated in this codebase (the `PerasCertDB`, `PerasVoteDB`, and weight infrastructure are all present and wired into `ChainSel`).
- The slot-gap condition (forecast horizon exceeded) is a normal occurrence during initial sync and after network partitions.
- The code itself carries a `TODO` comment acknowledging the bug and linking to issue `https://github.com/tweag/cardano-peras/issues/64`, confirming the developers are aware it is incorrect.
- No special privileges are required: any peer serving a valid Peras-boosted chain with a slot gap triggers the path.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read from the `PerasCertDB` (already available via `ChainDB.getPerasWeightSnapshot`). The `checkTime` / `readLedgerStateHelper` call site already runs inside an STM transaction, so the snapshot can be read atomically alongside `intersectsWithCurrentChain`.

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis = do
  WithFingerprint weights _ <- getPerasWeightSnapshot  -- read live snapshot
  if shouldSwitch $
       preferAnchoredCandidate (configBlock cfg) weights ourFrag theirFrag
    then pure ()
    else throwSTM $ CandidateTooSparse ...
```

---

### Proof of Concept

**Setup**: Peras is active; a certificate has been issued boosting block `B` on chain `C_peer` (peer's chain). `C_peer` has block count `N-2` but total Peras weight `N+10`. The node's current chain `C_ours` has block count `N` and total Peras weight `N` (no boosts). `C_peer` also has a slot gap larger than the forecast window between its intersection with `C_ours` and block `B`.

**Trigger**:
1. Peer sends header `H` at slot `S` (beyond forecast horizon).
2. `rollForward` calls `checkTime`, which calls `readLedgerStateHelper`.
3. `projectLedgerView S lst` returns `Nothing` (beyond forecast horizon).
4. `checkPreferTheirsOverOurs` is called.
5. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` compares block counts: `N` (ours) vs `N-2` (theirs) → `ShouldNotSwitch`.
6. Node throws `CandidateTooSparse` and disconnects.

**Result**: The node stays on `C_ours` (total Peras weight `N`) and never adopts `C_peer` (total Peras weight `N+10`), which is the Peras-canonical chain. The node is on the wrong chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1819)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-241)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
          }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs (L298-311)
```haskell
                , GSM.getCandidateOverSelection = do
                    weights <- ChainDB.getPerasWeightSnapshot chainDB
                    pure $ \(headers, _lst) state ->
                      case AF.intersectionPoint headers (csCandidate state) of
                        Nothing -> GSM.CandidateDoesNotIntersect
                        Just{} ->
                          GSM.WhetherCandidateIsBetter $ -- precondition requires intersection
                            shouldSwitch
                              ( preferAnchoredCandidate
                                  (configBlock cfg)
                                  (forgetFingerprint weights)
                                  headers
                                  (csCandidate state)
                              )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
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
