### Title
`checkPreferTheirsOverOurs` Uses `emptyPerasWeightSnapshot` Instead of Actual Peras Weights, Causing Incorrect Chain Selection Decisions - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When a ChainSync header arrives beyond the forecast horizon, `checkPreferTheirsOverOurs` decides whether to disconnect from the peer by comparing the candidate chain against the current selection. The comparison is performed with a hardcoded `emptyPerasWeightSnapshot` instead of the actual `PerasWeightSnapshot` held by the ChainDB. When Peras is enabled, this causes the node to ignore all certificate-based weight boosts during this critical disconnect decision, leading to incorrect chain selection outcomes.

---

### Finding Description

The function `checkPreferTheirsOverOurs` in `ChainSync/Client.hs` is called when a received header is beyond the ledger's forecast horizon. Its purpose is: if the candidate chain is not preferred over our current selection, disconnect from the peer (since we will never adopt it). The comparison is delegated to `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot` to account for Peras certificate boosts.

However, the call site hardcodes `emptyPerasWeightSnapshot` (a snapshot with no boosts at all) instead of reading the actual snapshot from the ChainDB:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← hardcoded empty, ignores real Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
```

The ChainDB exposes `getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))` and the actual snapshot is already read and used correctly in `chainSelectionForBlock` and `chainSelSync`. The `ChainDbView` record passed to the ChainSync client also carries `getChainComparison`, which internally reads the real snapshot. The correct value is available; it is simply not used here.

The analog to the external report is exact: the correct value (`referrers[edition_]` / actual `PerasWeightSnapshot`) is computed and stored, but the wrong value (`referrer_` / `emptyPerasWeightSnapshot`) is passed to the critical operation.

---

### Impact Explanation

When Peras is enabled and certificates have been issued, the `PerasWeightSnapshot` is non-empty. Two incorrect outcomes arise from using `emptyPerasWeightSnapshot`:

**Case 1 — Incorrect disconnection from an honest peer (chain selection failure):**
Suppose the candidate chain is shorter in block count than our current selection, but heavier in total Peras weight (because it contains certificate-boosted blocks). With the actual snapshot, `preferAnchoredCandidate` returns `ShouldSwitch` (candidate is heavier) → the node correctly keeps the connection. With `emptyPerasWeightSnapshot`, the comparison is purely by block count → `ShouldNotSwitch` → the node disconnects from the honest peer. The node then fails to adopt the correct, heavier canonical chain, causing it to remain on a lighter (less secure) chain.

**Case 2 — Failure to disconnect from an adversarial peer:**
Suppose our current selection has Peras-boosted blocks making it heavier, but the adversary's chain is longer in block count. With actual weights, `preferAnchoredCandidate` returns `ShouldNotSwitch` (ours is heavier) → disconnect. With `emptyPerasWeightSnapshot`, the adversary's longer-in-block-count chain appears preferred → the node does not disconnect, continuing to process adversarial headers.

Both cases represent a chain selection bug: the node makes incorrect keep/disconnect decisions based on a weight comparison that ignores the Peras protocol's certificate boosts, violating the Peras chain selection invariant.

---

### Likelihood Explanation

- Peras is currently disabled by default, but the code is production-ready and the bug is present in the production path.
- When Peras is enabled, any peer can trigger this code path by sending headers beyond the forecast horizon — no special privileges required.
- The scenario requires Peras certificates to have been issued (non-empty `PerasWeightSnapshot`), which is the normal operating condition when Peras is active.
- The developers have acknowledged the issue with a `TODO` comment referencing issue #64, but the fix has not been applied.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` with the actual `PerasWeightSnapshot` read from the ChainDB. The `ChainDbView` already provides access to the snapshot via `getChainComparison` (which internally reads `getPerasWeightSnapshot`). The fix should read the actual snapshot atomically and pass it to `preferAnchoredCandidate`:

```haskell
checkPreferTheirsOverOurs kis = do
  weights <- forgetFingerprint <$> ChainDB.getPerasWeightSnapshot chainDB
  if shouldSwitch $
       preferAnchoredCandidate (configBlock cfg) weights ourFrag theirFrag
    then pure ()
    else throwSTM $ CandidateTooSparse ...
```

Alternatively, if the intent of the TODO is to remove this check entirely (as noted in issue #64), the check should be removed rather than patched.

---

### Proof of Concept

The root cause is at: [1](#0-0) 

The hardcoded `emptyPerasWeightSnapshot` is passed to `preferAnchoredCandidate` instead of the actual snapshot: [2](#0-1) 

The correct snapshot is available via `getPerasWeightSnapshot` on the ChainDB API: [3](#0-2) 

The same `preferAnchoredCandidate` function correctly uses the actual snapshot everywhere else in the chain selection pipeline: [4](#0-3) 

The `weightedSelectView` and `preferAnchoredCandidate` functions are designed to use the real snapshot for Peras-aware comparisons: [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
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
