### Title
Peras Weight Snapshot Silently Ignored in `checkPreferTheirsOverOurs`, Causing Incorrect Chain-Selection Disconnect — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` guard inside the ChainSync client always substitutes `emptyPerasWeightSnapshot` for the real Peras certificate-weight snapshot when deciding whether to disconnect from a peer whose candidate header is beyond the forecast horizon. This is structurally identical to the reported NFT bug: an optional/missing component (the price oracle / the weight snapshot) causes a critical evaluation step to be silently skipped, so the node makes the wrong decision — disconnecting from a peer whose Peras-boosted chain is actually the canonical one.

---

### Finding Description

When a candidate header arrives that is beyond the current forecast horizon, the ChainSync client calls `checkPreferTheirsOverOurs` to decide whether to keep syncing with that peer or throw `CandidateTooSparse` and disconnect:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always zero; real weights never consulted
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse
          mostRecentIntersection
          (ourTipFromChain ourFrag)
          (theirTipFromChain theirFrag)
``` [1](#0-0) 

`preferAnchoredCandidate` has two code paths: when the snapshot is empty it falls back to a pure block-count comparison; when it is non-empty it computes the full Peras-weighted total weight of each suffix:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- pure block-count / selectView comparison
      ...
  | otherwise =
      -- weighted comparison using certificate boosts
      ...
``` [2](#0-1) 

Because `emptyPerasWeightSnapshot` is always passed, the `otherwise` branch is never reached inside `checkPreferTheirsOverOurs`. The Peras certificate boosts recorded in `PerasWeightSnapshot` — which are populated by `chainSelSync` when a `ChainSelAddPerasCert` message is processed — are completely invisible to this guard. [3](#0-2) 

The actual chain-selection path in `ChainSel.hs` correctly reads the live weight snapshot via `getPerasWeightSnapshot` and passes it through `constructPreferableCandidates` → `chainSelection`. The disconnect guard in the ChainSync client does not. [4](#0-3) 

---

### Impact Explanation

Consider a network running Peras where the canonical chain has accumulated certificate boosts. Suppose:

- **Honest peer's chain**: 10 blocks, 2 Peras-boosted blocks (each carrying weight boost B) → total Peras weight = 10 + 2B
- **Adversary's chain**: 11 blocks, 0 Peras-boosted blocks → total Peras weight = 11

With the real snapshot, `preferAnchoredCandidate` returns `ShouldSwitch` for the honest peer's chain (10 + 2B > 11 when B ≥ 1) and `ShouldNotSwitch` for the adversary's chain. The node keeps syncing with the honest peer and disconnects from the adversary.

With `emptyPerasWeightSnapshot`, the comparison degrades to pure block count: 10 < 11, so `shouldSwitch` returns `False` for the honest peer. The node throws `CandidateTooSparse` and **disconnects from the honest peer**, while continuing to sync with the adversary. If the honest peer was the only source of the Peras-boosted canonical chain, the node permanently misses it and adopts the adversary's lighter chain.

This is a **High** chain-selection bug: an unprivileged peer can craft a slightly-longer but unboosted chain to cause an honest node to reject the canonical Peras-boosted chain when that chain's tip is beyond the forecast horizon.

---

### Likelihood Explanation

The condition is reachable whenever:
1. Peras certificates have been issued (normal operation once Peras is active).
2. A candidate header arrives beyond the forecast horizon — a routine occurrence during initial sync or after a network partition.
3. An adversary (or even a slow honest peer) presents a chain that is longer by block count but lighter by Peras weight than the canonical chain.

No key compromise, stake majority, or privileged access is required. The adversary only needs to serve a valid but unboosted chain of sufficient length.

---

### Recommendation

Pass the live `PerasWeightSnapshot` (already available in the `ConfigEnv` / `ChainDbView` context) to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, mirroring how it is used in `constructPreferableCandidates` and `chainSelectionForBlock`. The existing TODO comment (`-- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64`) acknowledges the problem; until the check is removed entirely, it must use the real weights to avoid incorrect disconnections.

---

### Proof of Concept

1. Peras is active; the canonical chain tip is beyond the local forecast horizon.
2. The canonical chain has N blocks and M certificate boosts; total Peras weight = N + M·B.
3. An adversary serves a chain with N+1 blocks and zero boosts; total Peras weight = N+1.
4. Assume M·B > 1 (e.g., one boost with B = 2): canonical weight = N+2 > N+1.
5. ChainSync client receives the adversary's header (beyond forecast horizon) and calls `checkPreferTheirsOverOurs` for the **honest** peer.
6. `preferAnchoredCandidate … emptyPerasWeightSnapshot ourFrag theirFrag` compares block counts only: honest peer has N blocks vs. our N blocks → `ShouldNotSwitch`.
7. Node throws `CandidateTooSparse` and disconnects from the honest peer.
8. Node continues syncing with the adversary's N+1-block chain.
9. Actual chain selection (`chainSelSync`) would have preferred the honest chain (N+2 > N+1), but the honest peer was already disconnected; the node adopts the adversary's non-canonical chain. [5](#0-4) [6](#0-5) [3](#0-2)

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
