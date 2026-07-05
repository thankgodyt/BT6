### Title
ChainSync Client `checkPreferTheirsOverOurs` Uses Empty Peras Weight Snapshot, Causing Incorrect Peer Disconnection Under Peras - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When a peer's header is beyond the local forecast horizon, the ChainSync client must decide whether to keep waiting (if the candidate chain is still preferable) or disconnect (if it is not). This decision is made in `checkPreferTheirsOverOurs`. However, this function hardcodes `emptyPerasWeightSnapshot` instead of reading the actual current Peras weight snapshot from the `PerasCertDB`. As a result, when Peras is active and a candidate chain's blocks carry Peras certificate weight boosts, the comparison ignores those boosts and may incorrectly conclude the candidate is not preferable, causing the node to disconnect from a peer whose chain is actually heavier (and thus canonically preferred) under Peras rules.

---

### Finding Description

In `checkPreferTheirsOverOurs` inside `checkTime` in `Client.hs`, the chain comparison is performed with `emptyPerasWeightSnapshot` hardcoded:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- <-- always empty, ignores real Peras weights
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

This function is called from `readLedgerStateHelper` when `projectLedgerView` returns `Nothing` (i.e., the header is beyond the forecast horizon). In that case, the code retries waiting for the local chain to advance, but only if `checkPreferTheirsOverOurs` does not throw `CandidateTooSparse`. The check is meant to prevent waiting indefinitely for a candidate that can never be preferred. [2](#0-1) 

The actual Peras weight snapshot is available via `getPerasWeightSnapshot` from the `ChainDB` API, and is correctly used in `chainSelectionForBlock` and `getCurrentChainLike`: [3](#0-2) [4](#0-3) 

The `preferAnchoredCandidate` function, when given a non-empty weight snapshot, computes `weightedSelectView` over the suffix after the intersection, incorporating Peras certificate boosts into the comparison. With an empty snapshot, it falls back to pure block-number comparison, ignoring any boosts. [5](#0-4) 

The code itself acknowledges this is a known issue with a `TODO` comment referencing `https://github.com/tweag/cardano-peras/issues/64`.

---

### Impact Explanation

**High — Chain selection error that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

When Peras is active, a candidate chain whose blocks are boosted by Peras certificates may be the canonically preferred chain (heavier total weight) even if it has fewer blocks than the local selection. If such a candidate's next header falls beyond the forecast horizon, `checkPreferTheirsOverOurs` evaluates the comparison without Peras weights. If the candidate has fewer blocks than the local chain (but more total Peras weight), the check incorrectly concludes `ShouldNotSwitch` and throws `CandidateTooSparse`, disconnecting from the peer.

The consequence is that the honest node:
1. Disconnects from a peer offering the canonically heavier (Peras-preferred) chain.
2. Retains its current, lighter chain.
3. Diverges from the honest majority that has adopted the heavier chain.

This is a chain-selection bug that causes an honest node to prefer a less-secure (lighter) chain over the canonical one, violating the Peras safety guarantee that certificate-boosted chains should be preferred.

---

### Likelihood Explanation

**Medium-High when Peras is enabled.** The condition requires:
1. Peras is active (currently being deployed).
2. A candidate chain has Peras-boosted blocks that make it heavier than the local chain despite having fewer blocks.
3. The candidate's next header falls beyond the local forecast horizon (a normal occurrence when the intersection is near the stability window boundary).

Conditions 2 and 3 can arise naturally during normal operation, particularly during chain forks near epoch boundaries or when a node is slightly behind. An adversary can deliberately craft a scenario by withholding blocks to push the intersection near the forecast boundary, then presenting a Peras-boosted fork.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the actual current Peras weight snapshot read from the `ChainDB`. Since `checkPreferTheirsOverOurs` runs inside an STM transaction (`readLedgerStateHelper` calls it via `atomically`), the snapshot should be read atomically from `getPerasWeightSnapshot` (which is an `STM m` action):

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot chainDbView
  if shouldSwitch $
       preferAnchoredCandidate (configBlock cfg) weights ourFrag theirFrag
    then pure ()
    else throwSTM $ CandidateTooSparse ...
```

The `ChainDbView` already provides `getPerasWeightSnapshot` as an STM action, so this is a straightforward fix. The referenced issue `https://github.com/tweag/cardano-peras/issues/64` tracks this exact problem.

---

### Proof of Concept

**Setup:** Peras is enabled. The local node has chain `A → B → C` (3 blocks, no Peras boosts). A peer offers chain `A → B → D` where block `D` is boosted by a Peras certificate giving it weight `W > 1`. The total weight of the peer's chain is `2 + W > 3`, so it is canonically preferred.

**Trigger:** Block `D` is in a slot beyond the local forecast horizon (e.g., the intersection is at `B`, and `D`'s slot is more than `stabilityWindow` slots ahead of `B`).

**Execution path:**
1. ChainSync client receives header `D` from the peer.
2. `rollForward` calls `checkTime`.
3. `checkTime` calls `readLedgerState` → `readLedgerStateHelper`.
4. `projectLedgerView slotOf(D) lst` returns `Nothing` (beyond forecast horizon).
5. `checkPreferTheirsOverOurs` is called with `kis` where `theirFrag = [B, D]` and `ourFrag = [B, C]`.
6. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` compares block numbers: `ourFrag` tip has `BlockNo 3`, `theirFrag` tip has `BlockNo 3` (same length). With no Peras weights, this returns `ShouldNotSwitch EQ`.
7. `checkPreferTheirsOverOurs` throws `CandidateTooSparse`, disconnecting from the peer.
8. The node retains chain `A → B → C` (lighter) and never adopts the heavier `A → B → D`.

**Result:** The honest node diverges from the Peras-canonical chain, violating chain selection safety under Peras. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
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
