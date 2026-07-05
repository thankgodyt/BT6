### Title
`checkPreferTheirsOverOurs` Ignores Peras Weight Boosts While Actual Chain Selection Does Not, Causing Incorrect Peer Disconnection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client evaluates whether a peer's chain is preferred using `emptyPerasWeightSnapshot` (zero Peras weight boosts), while the actual chain selection in `ChainSel.hs` evaluates the same comparison using the real `PerasWeightSnapshot` (non-zero Peras weight boosts). This is a direct structural analog of the Deriverse margin-call detection bug: a detection/guard function uses a different parameter set than the enforcement function, creating a systematic discrepancy between when the node decides to disconnect from a peer and when it would actually adopt that peer's chain.

---

### Finding Description

When a peer's header is beyond the forecast horizon, the ChainSync client calls `checkPreferTheirsOverOurs` to decide whether to keep the peer connection or throw `CandidateTooSparse` and disconnect: [1](#0-0) 

The critical line is the hardcoded `emptyPerasWeightSnapshot` passed to `preferAnchoredCandidate`: [2](#0-1) 

The actual chain selection in `ChainSel.hs` uses the real `weights` (a live `PerasWeightSnapshot`) for the same `preferAnchoredCandidate` call: [3](#0-2) 

`preferAnchoredCandidate` branches on `isEmptyPerasWeightSnapshot`: when the snapshot is empty it falls back to pure block-count comparison; when non-empty it computes the full Peras-weighted comparison: [4](#0-3) 

`WeightedSelectView` combines block number with Peras weight boost, so two chains of equal block count can differ in total weight: [5](#0-4) 

The developers acknowledge this is wrong with an explicit TODO: [6](#0-5) 

---

### Impact Explanation

When Peras is active and has issued certificates that boost blocks on a peer's chain, the following scenario arises:

1. Peer A (honest) serves a chain of equal block count to the node's current chain, but with Peras weight boosts that make it strictly preferred by `chainSelection`.
2. Peer A's chain extends beyond the forecast horizon, triggering `checkPreferTheirsOverOurs`.
3. `checkPreferTheirsOverOurs` evaluates `preferAnchoredCandidate` with `emptyPerasWeightSnapshot`, sees equal block count, concludes "not preferred", and throws `CandidateTooSparse`, disconnecting from Peer A.
4. Peer B (adversary) serves a chain one block longer (preferred by block count alone, so `checkPreferTheirsOverOurs` passes), but which is not the Peras-preferred chain.
5. The node stays connected to Peer B, adopts the adversary's chain, and is permanently disconnected from the honest peer serving the Peras-preferred chain.

The node ends up following a chain that `chainSelection` itself would not prefer over the honest chain — a chain selection divergence from the intended Peras security model. This matches the **High** impact category: a chain selection bug that lets an unprivileged peer cause an honest node to prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

This requires Peras to be active and issuing certificates that boost blocks. Once Peras is live on mainnet, any peer whose chain is preferred only by Peras weight (not block count) and whose tip is beyond the forecast horizon will trigger incorrect disconnection. An adversary who can serve a chain one block longer than the honest Peras-preferred chain can reliably exploit this to isolate a node from the honest Peras-weighted chain. The entry path is a standard ChainSync peer connection — no special privileges required.

---

### Recommendation

Pass the real `PerasWeightSnapshot` (the same `weights` used in `ChainSel`) to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, so the disconnection decision uses the same chain-preference criteria as the actual chain selection. The TODO comment already identifies this as the intended fix. The `weights` snapshot must be made available to the ChainSync client environment, or the check must be restructured so it is evaluated inside `ChainSel` where `weights` is already present.

---

### Proof of Concept

**Setup:** Peras is active; the node's current chain has tip at block N with no Peras boost. Honest peer serves a chain also at block N but with a Peras certificate boosting its tip (total weight > N). Adversary serves a chain at block N+1 (no Peras boost, total weight = N+1).

**Step 1:** Honest peer's next header (block N+1 on their chain) is beyond the forecast horizon. `checkPreferTheirsOverOurs` is called.

**Step 2:** `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` — both fragments have the same block count (N), `emptyPerasWeightSnapshot` means no weight boost is considered, result is `ShouldNotSwitch EQ`.

**Step 3:** `checkPreferTheirsOverOurs` throws `CandidateTooSparse`. Node disconnects from honest peer.

**Step 4:** Adversary's chain (block N+1, no Peras boost) passes `checkPreferTheirsOverOurs` because it is longer by block count. Node adopts adversary's chain.

**Step 5:** `chainSelection` with real `weights` would have preferred the honest chain (Peras-boosted weight > N+1), but the honest peer is already disconnected. The node is now on the adversary's chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1132)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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
```
