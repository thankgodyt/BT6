### Title
ChainSync Client Uses Empty Peras Weight Snapshot in Forecast-Horizon Disconnect Check, Diverging from Actual Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` guard inside the ChainSync client's `readLedgerState` helper unconditionally passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate`, while the real chain-selection logic in `chainSelectionForBlock` reads the live `PerasWeightSnapshot` from the ChainDB. When Peras is active and a peer's candidate chain is preferred only because of Peras block-weight boosts, the ChainSync client will incorrectly conclude the candidate is not preferred and disconnect from that peer. An honest node can therefore be made to sever its connection to a legitimate peer offering the canonical Peras-boosted chain, causing it to remain on a less-preferred (non-canonical) chain.

---

### Finding Description

**Inconsistent weight snapshot in the forecast-horizon disconnect guard**

When the ChainSync client receives a header whose slot is beyond the current forecast horizon, it cannot yet obtain a `LedgerView` to validate the header. It blocks, waiting for the local chain to advance. While blocked it calls `checkPreferTheirsOverOurs` to decide whether to keep the connection:

```haskell
-- Client.hs ~1834-1851
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, ignores live Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

The actual chain-selection path in `chainSelectionForBlock` reads the live snapshot atomically:

```haskell
-- ChainSel.hs ~629-634
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [2](#0-1) 

`preferAnchoredCandidate` branches on whether the snapshot is empty:

```haskell
-- AnchoredFragment.hs ~186-213
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- uses plain SelectView / block-number comparison
      ...
  | otherwise =
      -- uses WeightedSelectView including Peras boosts
      ...
``` [3](#0-2) 

The two code paths therefore evaluate chain preference with fundamentally different criteria. The disconnect guard uses the empty-snapshot branch (block-number only), while chain selection uses the weighted branch (block-number + Peras boosts).

---

### Impact Explanation

When Peras is active, a candidate chain can be preferred over the local chain solely because it contains Peras-boosted blocks, even if it has the same or fewer raw blocks. In that scenario:

1. The peer's tip header arrives beyond the forecast horizon.
2. `checkPreferTheirsOverOurs` evaluates preference with `emptyPerasWeightSnapshot` → concludes the candidate is **not** preferred → throws `CandidateTooSparse` → disconnects.
3. The actual chain-selection logic, had it been reached, would have evaluated the same candidate with the live Peras weights → concluded it **is** preferred → adopted it.

The honest node is therefore severed from a legitimate peer offering the canonical Peras-boosted chain and remains on a less-preferred (non-canonical) chain. This is a chain-selection bug that causes an honest node to prefer a non-canonical chain beyond the intended security assumptions of the Peras protocol.

**Impact class:** High — chain-selection bug that lets an unprivileged peer (or the absence of one) make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

- **Peras activation required.** The bug is dormant while `PerasWeightSnapshot` is always empty (pre-Peras). Once Peras is activated on a network, the bug becomes reachable on every node.
- **Forecast-horizon condition required.** The guard fires only when a header is beyond the forecast horizon. This occurs naturally during bulk sync or when a peer's chain has a large slot gap, both of which are common operational conditions.
- **No attacker privilege required.** Any peer can present a Peras-boosted candidate chain. The node's own ChainSync client triggers the disconnect autonomously.
- **The TODO comment** (`-- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64`) confirms the developers are aware the check is incorrect in the Peras context but have not yet removed or corrected it.

---

### Recommendation

**Short term:** Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` read from the ChainDB (the same snapshot used by `chainSelectionForBlock`), so the disconnect guard and the actual chain-selection logic evaluate preference identically.

**Long term:** As the TODO comment notes, consider removing `checkPreferTheirsOverOurs` entirely (tracking issue `https://github.com/tweag/cardano-peras/issues/64`), since the check is a heuristic optimisation whose correctness depends on the chain-order definition remaining stable across all code paths.

---

### Proof of Concept

**Setup:** A private testnet with Peras active. Node A is syncing. Peer B offers a candidate chain whose tip has the same block number as Node A's tip but carries a Peras boost that makes it strictly preferred under `preferAnchoredCandidate` with real weights.

**Trigger sequence:**

1. Peer B sends a header whose slot is beyond Node A's current forecast horizon (e.g., a large slot gap exists on Peer B's chain).
2. Node A's ChainSync client enters `readLedgerState`, calls `checkPreferTheirsOverOurs`.
3. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` evaluates to `ShouldNotSwitch` (same block number, no boosts counted).
4. `throwSTM CandidateTooSparse` fires; Node A disconnects from Peer B.
5. Node A never reaches `chainSelectionForBlock` for Peer B's chain.
6. Node A remains on its own chain, which is non-canonical under Peras.

**Key code references:**

- Disconnect guard with empty snapshot: [4](#0-3) 
- Live snapshot read in chain selection: [2](#0-1) 
- `preferAnchoredCandidate` branching on empty vs. live snapshot: [3](#0-2) 
- `emptyPerasWeightSnapshot` definition: [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
