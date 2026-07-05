### Title
Hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` Causes Incorrect Chain-Selection Disconnect Decision When Peras Is Active — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The ChainSync client's `checkPreferTheirsOverOurs` guard — which decides whether to disconnect from a peer whose candidate chain is beyond the forecast horizon — hardcodes `emptyPerasWeightSnapshot` (zero Peras weight) instead of using the live Peras weight snapshot. When Peras is active and the canonical chain carries Peras certificate boosts, this guard can incorrectly conclude that a peer's chain is not preferred and disconnect from it, causing the local node to follow a non-canonical, lighter chain.

---

### Finding Description

`checkPreferTheirsOverOurs` is invoked inside the ChainSync client whenever a candidate header lies beyond the current forecast horizon. Its purpose is: if the peer's chain is not even preferred over ours (ignoring the unvalidatable header), we should disconnect immediately because we will never adopt it.

The comparison is delegated to `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot` to account for Peras certificate boosts:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← hardcoded zero weights
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` branches on whether the snapshot is empty. When it is empty, it falls back to a pure block-count (longest-chain) comparison:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- pure block-count comparison (no Peras)
  | otherwise =
      -- weighted comparison using Peras boosts
``` [2](#0-1) 

The actual chain-selection logic in ChainDB uses the real, live `PerasWeightSnapshot`. The `checkPreferTheirsOverOurs` guard therefore uses a different, strictly weaker comparison than the one that governs actual adoption. The hardcoded empty snapshot is structurally identical to the `AmarokFacet` pattern: a value that should be a dynamic argument is instead fixed at a constant that is only correct in the degenerate (Peras-disabled) case.

---

### Impact Explanation

When Peras is active, the canonical chain can be shorter by block count but heavier by Peras certificate weight. A peer serving this canonical chain whose tip is beyond the local forecast horizon will trigger `checkPreferTheirsOverOurs`. Because the guard uses `emptyPerasWeightSnapshot`, it compares only block counts. If the canonical chain is shorter by block count than the local selection (but heavier by Peras weight), the guard concludes `ShouldNotSwitch` and throws `CandidateTooSparse`, disconnecting from the peer.

The node is now disconnected from an honest peer serving the canonical chain. It continues to extend a non-canonical, Peras-lighter chain. This is a chain-selection bug: an honest node is made to prefer a less-secure chain beyond the intended security assumptions of the Peras protocol.

**Impact category**: High — chain-selection bug that lets a normal network condition (canonical chain beyond forecast horizon) cause an honest node to follow a non-canonical chain.

---

### Likelihood Explanation

The trigger is a routine network condition: any peer whose canonical chain tip is beyond the local forecast horizon. No adversarial action is required. The bug fires automatically whenever:

1. Peras certificates have been issued (boosting some blocks on the canonical chain), and
2. The canonical chain is shorter by block count than the local selection (possible after a Peras-boosted fork), and
3. The canonical chain tip is beyond the local forecast horizon (normal during sync or after a network partition).

The TODO comment at line 1841 explicitly acknowledges this is a known gap tied to Peras integration (`https://github.com/tweag/cardano-peras/issues/64`), confirming the root cause is understood by the developers. Likelihood is conditional on Peras being active on the network.

---

### Recommendation

Pass the live `PerasWeightSnapshot` (already available in the `ConfigEnv` or `DynamicEnv` of the ChainSync client) to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, exactly as ChainDB does during actual chain selection. This ensures the disconnect decision is consistent with the adoption decision. The TODO comment at line 1841 already tracks this work.

---

### Proof of Concept

1. Peras is active; the committee issues certificates boosting blocks on chain **C** (canonical).
2. Chain **C** has block count `N` but Peras weight `W_C > W_local` (heavier than local chain **L** with block count `M > N`).
3. A peer **P** serves chain **C**; its tip is beyond the local forecast horizon.
4. `checkPreferTheirsOverOurs` is invoked with `emptyPerasWeightSnapshot`.
5. `preferAnchoredCandidate` falls into the block-count branch: `N < M` → `ShouldNotSwitch`.
6. `throwSTM CandidateTooSparse` fires; the node disconnects from **P**.
7. The node never adopts chain **C** and continues extending the non-canonical chain **L**.
8. The actual ChainDB chain-selection logic, if it were reached, would prefer **C** (because `W_C > W_local`), but it is never reached because the ChainSync client already disconnected. [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
