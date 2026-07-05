### Title
ChainSync Client Ignores Peras Certificate Weights in Forecast-Horizon Disconnection Check, Causing Chain Selection Failure - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs)

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client unconditionally passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate` when deciding whether to disconnect from a peer whose header is beyond the forecast horizon. This ignores all Peras certificate boosts. A peer serving a chain that is heavier than the local chain due to Peras boosts — but not longer by raw block count — will be incorrectly judged as "not preferred," causing the node to disconnect from that peer and permanently fail to adopt the correct, heavier chain.

### Finding Description

When a header from a peer is beyond the forecast horizon, `readLedgerStateHelper` calls `checkPreferTheirsOverOurs` before retrying:

```haskell
-- ChainSync/Client.hs lines 1814-1817
case prj lst of
  Nothing -> do
    checkPreferTheirsOverOurs kis'
    retry
```

`checkPreferTheirsOverOurs` evaluates whether the peer's fragment is preferred over ours:

```haskell
-- lines 1834-1857
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- <-- hardcoded empty, ignores all Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
```

`preferAnchoredCandidate` branches on whether the weight snapshot is empty:

```haskell
-- AnchoredFragment.hs lines 186-213
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- uses only block-count / SelectView comparison
      ...
  | otherwise =
      -- uses weighted suffix comparison (Peras-aware)
      ...
```

Because `emptyPerasWeightSnapshot` is always passed, the Peras-aware branch is never reached. The comparison falls back to raw block count / `SelectView` only. If the peer's chain has the same or fewer blocks than the local chain but carries a Peras certificate boost that makes it strictly heavier, `preferAnchoredCandidate` returns `ShouldNotSwitch`, and the client throws `CandidateTooSparse`, permanently disconnecting from that peer.

The actual Peras weight snapshot is available in the ChainDB (`getPerasWeightSnapshot`) and is used correctly everywhere else in chain selection (e.g., `chainSelectionForBlock`, `constructPreferableCandidates`), but is not threaded into this specific check.

### Impact Explanation

This is a **High** chain-selection bug. When Peras is active and a certificate boosts a block on a fork that is heavier but not longer than the local chain, the node will:

1. Receive headers from a peer serving the heavier (correct) chain.
2. Encounter a header beyond the forecast horizon.
3. Evaluate chain preference using zero Peras weights.
4. Conclude the peer's chain is not preferred.
5. Disconnect from the peer with `CandidateTooSparse`.
6. Never adopt the heavier, more secure chain.

The node remains on a less-secure chain indefinitely, violating the Peras chain-selection invariant that the heaviest chain should be preferred.

### Likelihood Explanation

This is reachable by any unprivileged peer serving a valid Peras-boosted chain. The code path is triggered whenever a header is beyond the forecast horizon — a normal occurrence during syncing or when a peer is slightly ahead. The TODO comment in the source explicitly acknowledges the defect is known and unresolved.

### Recommendation

Pass the actual `PerasWeightSnapshot` from the ChainDB into `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`. The snapshot is already available via `getPerasWeightSnapshot cdb` (an `STM` action) and is used correctly in all other chain-selection call sites. The fix mirrors the pattern already established in `chainSelectionForBlock` and `constructPreferableCandidates`.

### Proof of Concept

**Scenario:**
- Local chain: blocks A → B → C (block count 3, no Peras boost)
- Peer chain: blocks A → B → D (block count 3, D is boosted by a Peras certificate with weight > k)

**Steps:**
1. Peer sends header D, which is beyond the local forecast horizon.
2. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs`.
3. `preferAnchoredCandidate` is called with `emptyPerasWeightSnapshot`.
4. Since both chains have the same block count and `emptyPerasWeightSnapshot` forces the `SelectView`-only path, the peer's chain is judged equal or not preferred.
5. `throwSTM CandidateTooSparse` fires; the node disconnects.
6. The node never adopts the heavier chain containing D, even though D's Peras boost makes it the correct selection.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1817)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
