### Title
Out-of-Sync Chain-Weight Snapshot in `checkPreferTheirsOverOurs` Causes Incorrect Peer Disconnection Under Peras — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client evaluates whether a peer's candidate chain is preferred using a hardcoded `emptyPerasWeightSnapshot`, while the actual chain-selection logic in `ChainSel.hs` uses the real `PerasWeightSnapshot` (which includes Peras certificate weight boosts). When Peras is active, this out-of-sync metric causes the node to incorrectly disconnect from peers offering a chain that is genuinely heavier by total Peras weight, even though it has fewer blocks. The node then never adopts the canonical chain, silently diverging from the correct selection.

---

### Finding Description

When a received header is beyond the forecast horizon, `checkPreferTheirsOverOurs` is called to decide whether to keep the connection open or throw `CandidateTooSparse`:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← uses ZERO Peras weight
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` with a non-empty `PerasWeightSnapshot` computes total weight as `blockCount + Σ(perasBoosts)` over the suffix after the intersection:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- block-count-only path
      ...
  | otherwise =
      case AF.intersect ours cand of
        Just (_,_,oursSuffix,candSuffix) ->
          preferCandidate cfg
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
``` [2](#0-1) 

But the actual chain-selection in `constructPreferableCandidates` and `chainSelection` uses the real snapshot read from the ChainDB:

```haskell
ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
``` [3](#0-2) 

The two calls to `preferAnchoredCandidate` use **different weight snapshots** for the same decision. The guard check uses `emptyPerasWeightSnapshot`; the actual selection uses the live `weights`. This is structurally identical to the external report's pattern: an "optimistic" (here: weight-ignoring) value is used in the guard check, while the actual operation uses a different (correct) value.

---

### Impact Explanation

**Scenario (Peras active, peer's chain has Peras boosts):**

- Our chain: 10 blocks, no Peras boosts → total weight = 10
- Peer's chain: 8 blocks, Peras boost of 5 on two blocks → total weight = 8 + 10 = 18

With `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs`:
- Only block count is compared: 8 < 10 → `shouldSwitch = False` → `throwSTM CandidateTooSparse` → **disconnect**

With real weights in actual chain selection:
- Total weight compared: 18 > 10 → `shouldSwitch = True` → **would switch**

The node incorrectly disconnects from the peer offering the heavier canonical chain. It then remains on its lighter chain, diverging from the correct Peras chain selection. This is a **High** impact chain-selection bug: an honest node is made to prefer a non-canonical, less-secure chain beyond the intended security assumptions of the Peras protocol. [4](#0-3) 

---

### Likelihood Explanation

- Requires Peras to be active and producing certificate weight boosts on blocks.
- Triggered by any honest peer serving a chain that is heavier by Peras weight but shorter by block count — a normal and expected scenario under Peras (certificates boost recent blocks, making a shorter fork heavier).
- No privileged access required; any peer serving a valid Peras-boosted chain triggers the bug.
- The developers have already flagged this with a `TODO` comment referencing issue `cardano-peras#64`, confirming the defect is known but unresolved in the current codebase. [5](#0-4) 

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` obtained from the ChainDB (the same snapshot used by `chainSelectionForBlock`). The `KnownIntersectionState` or the `ChainDbView` interface should be extended to supply the current weight snapshot to this STM action, so that the guard check and the actual chain-selection logic use the same metric. [6](#0-5) 

---

### Proof of Concept

**Setup:**
- `k = 10`, Peras active
- Our chain: blocks B1…B10, no Peras boosts → `totalWeight(ourFrag) = 10`
- Peer's chain: forks at B5, adds blocks B6′, B7′, B8′ (3 blocks), each with Peras boost 4 → `totalWeight(theirFrag suffix) = 3 + 12 = 15`

**Step 1 — Peer sends header B8′ (beyond forecast horizon):**
`checkTime` calls `readLedgerStateHelper`, which calls `checkPreferTheirsOverOurs`.

**Step 2 — Guard check with `emptyPerasWeightSnapshot`:**
```
preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag
  → compares blockNo(ourTip=B10) vs blockNo(theirTip=B8′)
  → 10 > 8 → ShouldNotSwitch
  → throwSTM CandidateTooSparse  ← INCORRECT DISCONNECT
``` [7](#0-6) 

**Step 3 — What actual chain selection would decide (never reached):**
```
preferAnchoredCandidate cfg realWeights ourFrag theirFrag
  → totalWeight(ourSuffix after intersection) = 5
  → totalWeight(theirSuffix after intersection) = 3 + 12 = 15
  → 15 > 5 → ShouldSwitch  ← CORRECT: should adopt peer's chain
``` [8](#0-7) 

The node disconnects from the peer, never fetches the heavier chain, and remains on the lighter (non-canonical) chain. The stale `emptyPerasWeightSnapshot` in the guard is the direct root cause — an exact structural analog to the out-of-sync leftover collateral value in the external report.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L774-778)
```haskell
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-37)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```
