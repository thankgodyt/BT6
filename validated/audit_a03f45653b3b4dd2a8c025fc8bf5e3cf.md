### Title
ChainSync Client Disconnects Peers Serving Peras-Heavier Chains Due to Inconsistent Weight Snapshot in `checkPreferTheirsOverOurs` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client performs a chain-preference check using a hardcoded `emptyPerasWeightSnapshot`, ignoring all Peras certificate boosts. The actual chain selection in `ChainDB` uses the real `PerasWeightSnapshot`. When Peras is enabled, a peer serving a chain that is shorter in block count but heavier due to Peras certificate boosts will be incorrectly disconnected by this check, even though the real chain selection would prefer that chain. The node is thus prevented from adopting the correct (heavier) chain.

---

### Finding Description

`checkPreferTheirsOverOurs` is invoked when a peer's header is beyond the forecast horizon and the node must decide whether to keep the connection. The check calls `preferAnchoredCandidate` with a hardcoded `emptyPerasWeightSnapshot`:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always ignores Peras certificate boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

The actual chain selection in `constructPreferableCandidates` and `chainSelection` reads the real `PerasWeightSnapshot` from the `PerasCertDB` and passes it to `preferAnchoredCandidate`:

```haskell
(succsOf, lookupBlockInfo, curChain, weights) <- atomically $ do
  ...
  <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [2](#0-1) 

`preferAnchoredCandidate` branches on whether the snapshot is empty. With a non-empty snapshot (Peras enabled), it computes `weightedSelectView` over the suffix after the intersection, which includes Peras certificate boosts. With `emptyPerasWeightSnapshot`, it falls back to pure block-count comparison: [3](#0-2) 

The `PerasWeightSnapshot` is populated by `implGetWeightSnapshot` in `PerasCertDB.Impl`, which derives weights from all stored certificates: [4](#0-3) 

**The inconsistency**: `checkPreferTheirsOverOurs` uses an empty snapshot (block-count only), while `chainSelection` uses the real snapshot (block-count + Peras boosts). When Peras is active and a peer's chain is shorter in block count but heavier due to certificate boosts, the two functions reach opposite conclusions about chain preference. The ChainSync client disconnects the peer; the ChainDB would have adopted the chain.

---

### Impact Explanation

When Peras is enabled and a Peras certificate boosts a block on a fork chain `C1` such that `C1` is heavier than the current chain `C2` but shorter in raw block count:

1. A peer serving `C1` sends a header beyond the forecast horizon.
2. `checkPreferTheirsOverOurs` evaluates `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag`. Since `C1` is shorter, this returns `ShouldNotSwitch`.
3. The ChainSync client throws `CandidateTooSparse` and disconnects the peer.
4. The node never downloads the blocks of `C1` and never runs real chain selection against it.
5. The node remains on `C2`, the lighter (less secure) chain, violating the Peras chain selection invariant.

This is a **High** impact chain selection bug: an honest node is made to prefer a non-canonical, lighter chain over the correct heavier chain, beyond the intended security assumptions of the Peras protocol extension.

---

### Likelihood Explanation

- Peras is an active protocol extension in this codebase (the `PerasCertDB`, `PerasWeightSnapshot`, and `WeightedSelectView` infrastructure is fully wired into production chain selection).
- The scenario requires a Peras certificate to boost a block on a fork that is shorter in block count than the current selection. This is a normal Peras operating condition: certificates are designed to boost shorter forks to make them preferred.
- The trigger condition (header beyond forecast horizon) occurs routinely during syncing and when there are large slot gaps.
- The TODO comment at line 1841 explicitly acknowledges the issue is known and unresolved. [5](#0-4) 

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the actual `PerasWeightSnapshot` read from the ChainDB (via the `ChainDbView` already available in the ChainSync client environment). The check must use the same weight snapshot as the real chain selection to ensure consistent decisions about peer retention. If reading the snapshot atomically in STM is a concern, the snapshot (with its `Fingerprint`) can be cached in `KnownIntersectionState` and refreshed on fingerprint changes, mirroring the pattern already used for the current chain fragment.

---

### Proof of Concept

**Setup**: Peras enabled. Current chain `C2` has blocks `[B1, B2, B3, B4, B5]` (length 5, no Peras boosts, weight = 5). Fork chain `C1` has blocks `[B1, B2, B3, B4']` (length 4) where `B4'` is boosted by a Peras certificate with boost weight 3, giving `C1` total weight = 4 + 3 = 7 > 5.

**Trigger**: Peer P serves `C1`. The header of `B4'` is beyond the forecast horizon (e.g., large slot gap after `B3`).

**Observed behavior**:
1. `checkPreferTheirsOverOurs` is called with `ourFrag = [B1..B5]`, `theirFrag = [B1..B4']`.
2. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` compares block counts: 5 vs 4 → `ShouldNotSwitch GT`.
3. `throwSTM (CandidateTooSparse ...)` — peer P is disconnected.

**Expected behavior** (with real weights):
1. `preferAnchoredCandidate cfg realWeightSnapshot ourFrag theirFrag` computes `weightedSelectView` over suffixes after intersection: `C2` suffix weight = 2 (blocks B4, B5), `C1` suffix weight = 1 + 3 = 4 (block B4' + boost) → `ShouldSwitch (Heavier ...)`.
2. Peer P is retained; blocks are downloaded; `chainSelection` adopts `C1`.

The node is stuck on the lighter chain `C2` (weight 5) instead of the correct chain `C1` (weight 7), violating the Peras chain selection invariant. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1834-1851)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L374-382)
```haskell
  (succsOf, lookupBlockInfo, curChain, weights) <- atomically $ do
    invalid <- forgetFingerprint <$> readTVar cdbInvalid
    (,,,)
      <$> ( ignoreInvalidSuc cdbVolatileDB invalid
              <$> VolatileDB.filterByPredecessor cdbVolatileDB
          )
      <*> VolatileDB.getBlockInfo cdbVolatileDB
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
