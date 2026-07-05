### Title
Inconsistent Peras Weight Snapshot in ChainSync Client Forecast-Horizon Preference Check - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when evaluating whether a candidate chain beyond the forecast horizon is preferred over the local selection. The rest of chain selection uses the real, live `PerasWeightSnapshot` from the ChainDB. This inconsistency — the same preference comparison function called with different weight contexts — is the direct analog of the external report's bug: a shared code path that applies the wrong logic in one of its calling contexts.

---

### Finding Description

When a peer sends a header that is beyond the current forecast horizon, the ChainSync client cannot yet validate it. Before blocking to wait for the local chain to advance, it calls `checkPreferTheirsOverOurs` to decide whether to stay connected or disconnect. The check is:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← hardcoded empty snapshot
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

The function `preferAnchoredCandidate` has two distinct code paths depending on whether the weight snapshot is empty:

- **Empty snapshot** (Peras disabled path): compares fragments purely by block count (`selectView` / `BlockNo`).
- **Non-empty snapshot** (Peras enabled path): computes `weightedSelectView` over the suffixes after the intersection, incorporating Peras weight boosts. [2](#0-1) 

The actual chain selection in `ChainSel.hs` uses the real `weights` from `cdbPerasWeightSnapshot`:

```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
``` [3](#0-2) 

The inconsistency: `checkPreferTheirsOverOurs` evaluates chain preference with **no Peras weights**, while the downstream chain selection evaluates it **with real Peras weights**. These two evaluations can disagree when Peras is active and a candidate chain contains boosted blocks.

---

### Impact Explanation

When Peras is active and a peer's candidate chain contains one or more Peras-boosted blocks, the following scenario arises:

1. The candidate chain has fewer blocks than our current chain (shorter by block count), but is heavier in total Peras weight.
2. The candidate's tip header is beyond the forecast horizon.
3. `checkPreferTheirsOverOurs` evaluates with `emptyPerasWeightSnapshot`: it sees the candidate as shorter → `ShouldNotSwitch` → **disconnects from the peer**.
4. The actual chain selection, had it been reached, would have evaluated with real weights and found the candidate heavier → `ShouldSwitch` → would have adopted the heavier chain.

The node incorrectly disconnects from a peer serving the legitimately heavier canonical chain. It then remains on a lighter (less secure) chain. This is a **chain selection error** that causes an honest node to prefer a non-canonical chain, directly matching the "High" impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

The code itself acknowledges the problem with a `TODO` comment referencing `https://github.com/tweag/cardano-peras/issues/64`.

---

### Likelihood Explanation

This requires Peras to be active (deployed) and a candidate chain to have Peras-boosted blocks that make it heavier by weight but shorter by block count than the local selection. Under Peras, certificates boost specific blocks, so a chain with even one boosted block can have higher total weight than a longer unboosted chain. Any peer serving such a chain beyond the forecast horizon triggers the bug. No special attacker capability is needed — an honest peer serving the canonical Peras-boosted chain is sufficient.

---

### Recommendation

Pass the real `PerasWeightSnapshot` (obtained from the ChainDB via `getPerasWeightSnapshot`) into `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`, so that the forecast-horizon preference check uses the same weight context as the actual chain selection. This is consistent with the existing `TODO` comment pointing to issue #64. The fix ensures that the two evaluations of `preferAnchoredCandidate` — the guard check and the actual chain selection — cannot disagree on which chain is heavier.

---

### Proof of Concept

**Setup**: Peras is active. The local chain has 10 blocks, none boosted. A peer's candidate chain has 9 blocks, with one block carrying a Peras boost of weight 2 (total weight = 11 > 10).

1. The peer sends the 9th header, which is beyond the forecast horizon (the local chain has not yet advanced far enough to forecast a ledger view for that slot).
2. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs` because `prj lst == Nothing`.
3. `checkPreferTheirsOverOurs` calls `preferAnchoredCandidate bcfg emptyPerasWeightSnapshot ourFrag theirFrag`.
4. With empty weights, `theirFrag` (9 blocks) is shorter than `ourFrag` (10 blocks) → `ShouldNotSwitch`.
5. The node throws `CandidateTooSparse` and disconnects from the peer.
6. The node never adopts the heavier Peras-boosted chain, remaining on the lighter 10-block chain. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1857)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView

  -- Note [Candidate comparing beyond the forecast horizon]
  -- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  --
  -- When a header is beyond the forecast horizon and their fragment is not
  -- preferrable to our selection (ourFrag), then we disconnect, as we will
  -- never end up selecting it.
  --
  -- In the context of Genesis, one can think of the candidate losing a
  -- density comparison against the selection. See the Genesis documentation
  -- for why this check is necessary.
  --
  -- In particular, this means that we will disconnect from peers who offer us
  -- a chain containing a slot gap larger than a forecast window.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L64-89)
```haskell
-- | Check that we can switch from @ours@ to @theirs@ by rolling back our chain
-- by at most @k@ weight.
--
-- If @ours@ and @cand@ do not intersect, this returns 'False'. If they do
-- intersect, then we check that the suffix of @ours@ after the intersection has
-- total weight at most @k@.
forksAtMostKWeight ::
  ( StandardHash blk
  , HasHeader b
  , HeaderHash blk ~ HeaderHash b
  ) =>
  PerasWeightSnapshot blk ->
  -- | By how much weight can we roll back our chain at most?
  PerasWeight ->
  -- | Our chain @ours@.
  AnchoredFragment b ->
  -- | Their chain @theirs@.
  AnchoredFragment b ->
  -- | Indicates whether their chain forks at most the given the amount of
  -- weight. Returns 'False' if the two fragments do not intersect.
  Bool
forksAtMostKWeight weights maxWeight ours theirs =
  case ours `AF.intersect` theirs of
    Nothing -> False
    Just (_, _, ourSuffix, _) ->
      totalWeightOfFragment weights ourSuffix <= maxWeight
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
