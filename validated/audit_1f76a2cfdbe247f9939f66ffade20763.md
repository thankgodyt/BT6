### Title
ChainSync Client Ignores Peras Vote Weight in `checkPreferTheirsOverOurs`, Causing Incorrect Peer Disconnection and Chain Selection Failure - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client evaluates whether a candidate chain is preferred over the local selection using only block count, by hardcoding `emptyPerasWeightSnapshot`. It ignores the actual Peras vote-weight boosts that are used by every other chain-selection site in the codebase. When Peras is active, this incomplete state aggregation causes the node to incorrectly disconnect from peers whose chains are genuinely heavier (and therefore canonical under Peras), leaving the node permanently on a lighter, non-canonical chain.

---

### Finding Description

The function `checkPreferTheirsOverOurs` is invoked inside the ChainSync client whenever a received header is beyond the current forecast horizon and the node must decide whether to keep waiting or disconnect from the peer. The decision is made by calling `preferAnchoredCandidate`, but the call is made with `emptyPerasWeightSnapshot` instead of the real `PerasWeightSnapshot` that is used everywhere else in chain selection:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← only block count is considered
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

When `emptyPerasWeightSnapshot` is passed, `preferAnchoredCandidate` falls into its non-Peras branch and compares only `SelectView` (essentially `BlockNo`):

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      ...
      (_ :> ourTip, _ :> theirTip) ->
        case preferCandidate
          (projectChainOrderConfig cfg)
          (selectView cfg (getHeader1 ourTip))   -- block-count only
          (selectView cfg (getHeader1 theirTip)) of ...
  | otherwise =
      -- Peras path: uses weightedSelectView (block count + vote boosts)
      ...
``` [2](#0-1) 

By contrast, every other chain-selection call site — `initialChainSelection`, `addBlockToChainDB`, `chainSelection`, `compareChainDiffs`, `rollbackExceedsSuffix` — passes the real `weights :: PerasWeightSnapshot blk` obtained from `ChainSelEnv`: [3](#0-2) 

The `WeightedSelectView` used by the real chain-selection path combines `BlockNo` with `wsvWeightBoost` (the sum of all Peras vote boosts on the suffix):

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

`checkPreferTheirsOverOurs` never consults `wsvWeightBoost`, so it is blind to the second source of chain weight — exactly the incomplete-aggregation pattern from the external report.

---

### Impact Explanation

Under Peras, a chain with fewer blocks but significant vote boosts can have strictly greater total weight than a longer chain with no boosts. When the ChainSync client is blocked on the forecast horizon and calls `checkPreferTheirsOverOurs`:

1. The peer's chain has fewer blocks than the local chain → `preferAnchoredCandidate` with `emptyPerasWeightSnapshot` returns `ShouldNotSwitch`.
2. The node throws `CandidateTooSparse` and disconnects from the peer.
3. The node remains on its current chain, which has more blocks but **less total Peras weight** — i.e., the non-canonical chain under Peras.
4. Because the peer is disconnected, the node may never receive the heavier chain, causing a persistent chain-selection failure.

This matches the **High** impact category: a chain-selection bug that causes an honest node to prefer a non-canonical, less-secure chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

The trigger condition — a peer's chain being heavier due to Peras vote boosts despite having fewer blocks — is a normal, intended operating condition of Peras. The forecast-horizon block (`prj lst == Nothing`) is also a routine occurrence during syncing or when a peer is slightly ahead. No special privileges, key compromise, or majority stake are required; any peer serving a legitimately boosted chain can trigger this path.

---

### Recommendation

Pass the real `PerasWeightSnapshot` (available in the `ConfigEnv` or `InternalEnv` of the ChainSync client) to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, consistent with every other chain-selection call site. The existing TODO comment at line 1841 references `https://github.com/tweag/cardano-peras/issues/64` and acknowledges the check should be removed or corrected; the fix should ensure the Peras weight is included before that removal.

---

### Proof of Concept

**Setup (private testnet with Peras active):**

- Local chain `C_local`: 100 blocks, no Peras boosts → total weight = 100.
- Peer chain `C_peer`: 95 blocks, Peras vote boosts summing to 10 → total weight = 105.
- `C_peer` tip is beyond the local forecast horizon (e.g., the peer is slightly ahead of the local ledger tip by more than one stability window).

**Execution:**

1. ChainSync client receives a header from `C_peer` beyond the forecast horizon.
2. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs` (line 1816).
3. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` compares `BlockNo 100` vs `BlockNo 95` → `ShouldNotSwitch GT`.
4. `CandidateTooSparse` is thrown; the peer is disconnected.
5. The real `chainSelection` in ChainDB, if it were called with the actual `weights`, would compute total weight 100 vs 105 and select `C_peer`.
6. The node remains on `C_local` (weight 100) and never adopts `C_peer` (weight 105), diverging from the canonical Peras chain. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1821-1851)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L762-777)
```haskell
              . NE.filter (not . Diff.rollbackExceedsSuffix weights curChain)
              -- Extend the diff with candidates fitting on @p@
              . Paths.extendWithSuccessors succsOf lookupBlockInfo
              $ diff
        -- We cannot reach the block from the current selection.
        | otherwise -> pure []
  let fragments =
        -- Trim fragments so that they follow the LoE, that is, they extend the LoE
        -- by at most @k@ blocks or are extended by the LoE.
        fmap (trimToLoE loeFrag) $
          diffs
  pure
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
```
