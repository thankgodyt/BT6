### Title
Peras-Weight-Blind `checkPreferTheirsOverOurs` Allows Incorrect Peer Disconnection During Forecast-Horizon Stall — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client evaluates whether a peer's candidate chain is preferred over the node's current chain using a hardcoded `emptyPerasWeightSnapshot` instead of the live Peras weight snapshot. This is a direct analog of the reported XSS vulnerability's incomplete prefix check: just as the image proxy only filters `data:image/` but passes `data:text/html` through, this function only evaluates chain preference by raw block count, silently ignoring Peras certificate weight boosts. When Peras is active, this incomplete comparison can cause the node to incorrectly disconnect from peers serving the Peras-heavier honest chain while continuing to track an adversary's chain that is longer by block count but lighter by Peras weight.

### Finding Description

`checkPreferTheirsOverOurs` is invoked when a peer's header is beyond the forecast horizon and the node must decide whether to disconnect. Its purpose is to drop peers whose chains can never be selected. The function calls `preferAnchoredCandidate` with a hardcoded `emptyPerasWeightSnapshot`:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always ignores Peras weight boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
```

`preferAnchoredCandidate` branches on `isEmptyPerasWeightSnapshot weights`. When the snapshot is empty (as hardcoded here), it falls into the block-count-only path and never computes the Peras-weighted suffix comparison:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- purely block-number comparison, no Peras weight
      ...
  | otherwise =
      -- correct Peras-weighted suffix comparison
      ...
```

The real production path in `NodeKernel.hs` correctly fetches the live snapshot via `ChainDB.getPerasWeightSnapshot chainDB`, but `checkPreferTheirsOverOurs` never receives it.

**Attack path:**

1. The honest chain accumulates Peras certificate boosts, making it heavier than a longer-by-block-count adversarial fork.
2. An adversary presents a chain that is longer by block count but carries no Peras weight.
3. The honest peer's Peras-heavier chain extends beyond the current forecast horizon.
4. `checkPreferTheirsOverOurs` evaluates the honest peer's chain using empty weights: their chain is shorter by block count → `shouldSwitch = False` → the node disconnects from the honest peer (`CandidateTooSparse`).
5. Simultaneously, the adversary's longer-by-block-count chain passes the same check (`shouldSwitch = True`) → the node continues tracking the adversary.
6. The node stops downloading the honest chain's blocks and remains on the adversary's (Peras-lighter) chain for the duration of the disconnection window.

### Impact Explanation

**Impact: High.** This is a chain selection bug triggered by an unprivileged peer. When Peras is active, the node can be made to disconnect from the honest chain's peer and remain on a non-canonical, Peras-lighter chain. The intended Peras security assumption — that a chain with sufficient certificate weight is preferred over a longer-by-block-count adversarial chain — is violated at the forecast-horizon decision point. The final ChainDB selection uses real weights, but the node loses access to the honest chain's blocks during the disconnection window, extending the time it spends on the adversarial chain.

### Likelihood Explanation

**Likelihood: Low.** Peras is not yet deployed on Cardano mainnet; the code itself carries a `TODO` acknowledging the issue. Exploitation requires Peras to be active, the honest chain to carry certificate boosts, and the adversary to produce a longer-by-block-count fork — a non-trivial but unprivileged capability once Peras is live.

### Recommendation

Pass the live `PerasWeightSnapshot` (obtained from `ChainDB.getPerasWeightSnapshot`) into `checkPreferTheirsOverOurs` so that `preferAnchoredCandidate` uses the correct Peras-weighted comparison. Alternatively, follow the existing TODO and remove the check entirely (as noted in `https://github.com/tweag/cardano-peras/issues/64`), which avoids the incorrect disconnection at the cost of not pruning forecast-stalled peers at this point.

### Proof of Concept

**Root cause — hardcoded empty snapshot:** [1](#0-0) 

**`preferAnchoredCandidate` silently skips Peras-weighted comparison when snapshot is empty:** [2](#0-1) 

**Production NodeKernel correctly fetches the live snapshot — absent from `checkPreferTheirsOverOurs`:** [3](#0-2) 

**`emptyPerasWeightSnapshot` definition — an empty map, zero weight for all blocks:** [4](#0-3) 

**Call site that triggers `checkPreferTheirsOverOurs` when forecast horizon is exceeded:** [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1817)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
```

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs (L298-311)
```haskell
                , GSM.getCandidateOverSelection = do
                    weights <- ChainDB.getPerasWeightSnapshot chainDB
                    pure $ \(headers, _lst) state ->
                      case AF.intersectionPoint headers (csCandidate state) of
                        Nothing -> GSM.CandidateDoesNotIntersect
                        Just{} ->
                          GSM.WhetherCandidateIsBetter $ -- precondition requires intersection
                            shouldSwitch
                              ( preferAnchoredCandidate
                                  (configBlock cfg)
                                  (forgetFingerprint weights)
                                  headers
                                  (csCandidate state)
                              )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
