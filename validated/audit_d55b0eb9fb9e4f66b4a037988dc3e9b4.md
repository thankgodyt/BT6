### Title
`checkPreferTheirsOverOurs` Uses `emptyPerasWeightSnapshot` Instead of Actual Peras Weights, Causing Incorrect Chain-Selection Comparison - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

In `checkPreferTheirsOverOurs`, the call to `preferAnchoredCandidate` is hardcoded to pass `emptyPerasWeightSnapshot` instead of the actual live Peras weight snapshot. This is the direct structural analog of the external report: the wrong variant of a comparison function is used in a critical path, producing an incorrect result that causes the node to make the wrong chain-selection decision.

---

### Finding Description

`checkPreferTheirsOverOurs` is invoked inside `readLedgerStateHelper` whenever the ledger state cannot forecast a `LedgerView` for the candidate header's slot (i.e., the header is beyond the forecast horizon). Its purpose is to disconnect from a peer whose candidate chain is not preferred over the node's current selection, preventing the node from waiting indefinitely for a chain it will never adopt.

The comparison is performed as:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← wrong parameter
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
```

`preferAnchoredCandidate` branches on whether the supplied `PerasWeightSnapshot` is empty:

- **Empty snapshot (current code):** falls into the non-Peras path, comparing chains by `selectView` — i.e., `BlockNo` plus `TiebreakerView` only.
- **Non-empty snapshot (correct):** falls into the Peras path, comparing chains by `weightedSelectView` — i.e., `wsvTotalWeight = PerasWeight(blockNo) + wsvWeightBoost`, where `wsvWeightBoost` accumulates the certificate weight of all Peras-certified blocks in the fragment suffix.

When Peras is active, a candidate chain can have the **same block number** as the node's current chain but a **strictly higher total weight** because it carries more Peras certificate boosts. With `emptyPerasWeightSnapshot`, `preferCandidate` sees equal `BlockNo` values and returns `ShouldNotSwitch EQ`, so `shouldSwitch` is `False` and the node throws `CandidateTooSparse`, disconnecting from the peer. With the actual weight snapshot, `preferCandidate` would see a higher `wsvTotalWeight` for the candidate and return `ShouldSwitch`, allowing the sync to continue.

The TODO comment in the source explicitly acknowledges the problem and references a tracking issue (`https://github.com/tweag/cardano-peras/issues/64`), confirming this is a known defect that has not yet been corrected in the production code path.

---

### Impact Explanation

**High — Chain-selection bug that causes an honest node to prefer a non-canonical, less-secure chain beyond the intended Peras security assumptions.**

When Peras is active, the canonical chain is defined by the highest `wsvTotalWeight`, not merely the longest chain. A node that incorrectly disconnects from every peer offering the Peras-preferred chain (same `BlockNo`, higher certificate weight) will be unable to adopt that chain. If the only remaining connected peers offer a chain with lower total weight, the node's selection diverges from the canonical Peras chain. Because the node actively disconnects rather than simply failing to switch, the divergence is not self-correcting until the node re-establishes connections and the offending header is no longer beyond the forecast horizon — a window that can span many slots.

An adversary who controls a minority of stake can amplify this: by forking at a point where the honest chain has accumulated Peras certificate boosts, the adversary's fork has the same `BlockNo` but zero boost. The bug causes the honest node to disconnect from honest peers whose fork-tip header happens to fall beyond the forecast horizon, leaving the adversary's lighter chain as the only candidate the node will accept.

---

### Likelihood Explanation

Peras is implemented in the production codebase and is gated by the `PerasWeightSnapshot` being non-empty at runtime. The trigger condition — a candidate header beyond the forecast horizon — arises naturally during initial sync or after a network partition, both of which are common operational events. The code path is reachable by any unprivileged peer simply by serving a chain whose next header slot exceeds the node's current forecast range (a gap larger than `3k/f` slots). No key material, stake majority, or privileged access is required to reach `checkPreferTheirsOverOurs`.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` with the actual live `PerasWeightSnapshot` in `checkPreferTheirsOverOurs`. The snapshot is already threaded through the rest of the chain-selection machinery (e.g., `chainSelectionForBlock`, `constructPreferableCandidates`, `NodeKernel`'s GSM check). Alternatively, if the check is to be removed entirely as the TODO suggests, it should be removed promptly rather than left in place with the wrong weights, since the current state silently produces incorrect disconnection decisions under Peras.

---

### Proof of Concept

1. Peras is active; the node's current chain has tip at block number `N` with Peras weight boost `W₁`.
2. An honest peer serves a fork also at block number `N` but with Peras certificate boost `W₂ > W₁` (e.g., more blocks on that fork were certified by the Peras committee).
3. The peer's next header falls beyond the node's forecast horizon (slot gap > `3k/f`).
4. `readLedgerStateHelper` calls `projectLedgerView`, which returns `Nothing`.
5. `checkPreferTheirsOverOurs` is invoked. It calls `preferAnchoredCandidate` with `emptyPerasWeightSnapshot`.
6. Both fragments have tip `BlockNo = N`; the non-Peras path compares `selectView` values, finds them equal, and returns `ShouldNotSwitch EQ`.
7. `shouldSwitch` is `False`; the node throws `CandidateTooSparse` and disconnects from the honest peer.
8. The node never adopts the Peras-preferred chain (`wsvTotalWeight = N + W₂`), remaining on the lighter chain (`wsvTotalWeight = N + W₁`), diverging from the canonical Peras selection.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
