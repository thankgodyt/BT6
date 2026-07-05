### Title
Peras Weight Boost Zeroed in Forecast-Horizon Chain Comparison Causes Incorrect Peer Disconnection and Non-Canonical Chain Preference - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client hardcodes `emptyPerasWeightSnapshot` (zero Peras weight boost) instead of the real weight snapshot when deciding whether to disconnect from a peer whose candidate header is beyond the forecast horizon. This is the direct structural analog of the reported "liquidation bonus is 0%" bug: just as the Solidity code sets `discount = 0` when `currentLTV > 1e18`, the Haskell code sets `wsvWeightBoost = 0` (via the empty snapshot) whenever a header crosses the forecast horizon. The result is that a node running Peras will incorrectly disconnect from peers offering a legitimately heavier chain, permanently preferring a lighter, non-canonical chain.

---

### Finding Description

`checkPreferTheirsOverOurs` is invoked inside `readLedgerStateHelper` whenever the ledger cannot yet forecast a ledger view for an incoming header (i.e., the header is beyond the forecast horizon). Its purpose is to disconnect from peers whose candidate fragment is not preferable to the local selection, so the node does not wait indefinitely for a chain it will never adopt.

The comparison is performed by calling `preferAnchoredCandidate`:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always zero weight boost
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` branches on `isEmptyPerasWeightSnapshot weights`. When the snapshot is empty (as it always is here), it falls into the non-Peras branch and compares chains purely by `selectView` — i.e., by block number alone, with zero weight boost:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- compares only by BlockNo / selectView, ignoring PerasWeight
      ...
  | otherwise =
      -- uses weightedSelectView: BlockNo + wsvWeightBoost
      ...
``` [2](#0-1) 

The correct total weight under Peras is `wsvBlockNo + wsvWeightBoost`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [3](#0-2) 

By passing `emptyPerasWeightSnapshot`, `wsvWeightBoost` is always `PerasWeight 0` for both fragments, so the comparison reduces to block count only — exactly the "bonus is 0" pattern from the external report.

The TODO comment at line 1841 explicitly acknowledges this is unresolved. [4](#0-3) 

---

### Impact Explanation

**Impact: High — Chain selection bug that causes an honest node to permanently prefer a non-canonical, lighter chain.**

When Peras is active, the canonical chain is the one with the highest total weight (`BlockNo + PerasWeightBoost`). A chain with fewer blocks but significant Peras certificate boosts can be the canonical chain. When such a chain's tip is beyond the forecast horizon:

1. `checkPreferTheirsOverOurs` evaluates the candidate using zero weight boost.
2. The candidate appears to have fewer blocks than the local selection → `ShouldNotSwitch`.
3. The node throws `CandidateTooSparse` and disconnects from the peer.
4. The node never adopts the heavier, canonical chain.
5. The node is permanently stuck on a lighter, non-canonical chain — a chain selection safety failure under Peras security assumptions.

This matches the allowed impact scope: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Likelihood: Medium.**

- Requires Peras to be active and certificates to have been issued, boosting some chain's weight above the block-count-only ordering. This is the normal operating condition once Peras is deployed.
- The forecast-horizon condition (`projectLedgerView` returning `Nothing`) is a routine occurrence during syncing whenever a peer's headers are more than `3k/f` slots ahead of the intersection with the local selection.
- No special privileges, keys, or stake majority are required. Any peer serving a Peras-boosted chain that happens to be beyond the forecast horizon triggers the bug.
- The adversary's role is passive: they only need to have served a longer-by-block-count chain earlier, causing the node to adopt it as its current selection. The honest peer's heavier chain is then incorrectly rejected.

---

### Recommendation

Pass the real `PerasWeightSnapshot` (obtained from the ChainDB, as done in `BlockFetch/ClientInterface.hs` via `getPerasWeightSnapshot`) to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, instead of `emptyPerasWeightSnapshot`. This is already tracked as the intended fix in the referenced issue (`https://github.com/tweag/cardano-peras/issues/64`). Until resolved, `checkPreferTheirsOverOurs` must not be used in Peras-enabled deployments, or the forecast-horizon disconnection logic must be disabled when Peras weight boosts are present.

---

### Proof of Concept

**Setup (private testnet, Peras enabled):**

1. Node N has selected chain A: blocks `[G, B1, B2, B3, B4, B5]` (6 blocks, no Peras certificates, total weight = 6).
2. Honest peer P serves chain B: blocks `[G, B1, B2, C3, C4]` (5 blocks), but `C3` and `C4` are covered by Peras certificates granting a weight boost of +3 each. Total weight of B = 5 + 6 = 11 > 6.
3. Chain B is the canonical chain under Peras.
4. Chain B's tip `C4` is at a slot beyond the forecast horizon of N's intersection with B (i.e., more than `3k/f` slots ahead of `B2`).

**Trigger:**

5. P sends `MsgRollForward C4` to N.
6. N calls `checkTime`, which calls `readLedgerStateHelper`.
7. `projectLedgerView` returns `Nothing` (beyond forecast horizon).
8. N calls `checkPreferTheirsOverOurs` with `emptyPerasWeightSnapshot`.
9. `preferAnchoredCandidate` compares: our suffix has 3 blocks (`B3,B4,B5`), their suffix has 2 blocks (`C3,C4`). With zero weight boost, `ShouldNotSwitch`.
10. N throws `CandidateTooSparse` and disconnects from P.

**Result:** N remains on chain A (total weight 6), never adopting the canonical chain B (total weight 11). The node has permanently selected a non-canonical chain without any operator fault. [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
