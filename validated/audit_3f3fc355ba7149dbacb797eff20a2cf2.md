### Title
Inconsistent Chain Comparison Metric in `checkPreferTheirsOverOurs` vs Actual Chain Selection Allows Adversary to Cause Disconnection from Honest Peers - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The ChainSync client's `checkPreferTheirsOverOurs` guard uses `emptyPerasWeightSnapshot` (block-number-only comparison) to decide whether to disconnect from a peer, while the actual chain selection in `ChainSel.hs` uses the real `PerasWeightSnapshot` (total weight = block number + Peras boost). When Peras is active, these two code paths produce contradictory decisions for the same candidate chain, allowing an adversary to cause a node to disconnect from honest peers serving the heaviest (canonical) chain while retaining connections to adversarial peers serving a lighter chain.

---

### Finding Description

**Path 1 — Peer-disconnect guard (`checkPreferTheirsOverOurs`):** [1](#0-0) 

The function hardcodes `emptyPerasWeightSnapshot`, meaning it compares chains purely by block number (`BlockNo`). The TODO comment acknowledges this is wrong but the fix has not been applied:

```haskell
preferAnchoredCandidate
  (configBlock cfg)
  -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
  emptyPerasWeightSnapshot   -- ← always ignores Peras boost
  ourFrag
  theirFrag
```

**Path 2 — Actual chain selection (`constructPreferableCandidates` / `chainSelection`):** [2](#0-1) 

```haskell
ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
```

Here `weights` is the live `PerasWeightSnapshot`, so the comparison is by **total weight** (block number + Peras boost).

**The two comparison functions diverge when Peras is active:**

`preferAnchoredCandidate` with `emptyPerasWeightSnapshot` falls into the non-Peras branch: [3](#0-2) 

It compares only `selectView` (block number + tiebreaker). With real weights it falls into the Peras branch: [4](#0-3) 

which computes `wsvTotalWeight = BlockNo + PerasBoost`: [5](#0-4) 

The pre-filtering step in `constructPreferableCandidates` also uses real weights via `rollbackExceedsSuffix`: [6](#0-5) 

---

### Impact Explanation

When Peras is active, consider:

- **Our chain**: N blocks, no Peras boosts → total weight = N  
- **Honest peer's chain**: N blocks, with Peras boosts → total weight = N + boost > N  
- **Adversary's chain**: N+1 blocks, no Peras boosts → total weight = N+1

`checkPreferTheirsOverOurs` (block-number only):
- Honest peer: N == N → **not strictly preferred → disconnect honest peer**
- Adversary: N+1 > N → preferred → keep adversary connection

Actual chain selection (total weight):
- Honest peer: N + boost > N → **preferred → would switch to honest chain**
- Adversary: N+1 > N → preferred (if N+1 < N + boost, adversary is actually weaker)

The node disconnects from the honest peer serving the canonical (heaviest) chain and retains the adversary's connection. The node then cannot adopt the best chain, causing a chain selection failure. This matches the **High** impact category: a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

---

### Likelihood Explanation

**Medium-High** once Peras is active on a network. The adversary needs only to produce one additional block beyond the honest chain tip (achievable with any nonzero stake) to satisfy the block-number comparison in `checkPreferTheirsOverOurs`. The honest peer's chain, which has equal block count but more Peras weight, is then unconditionally disconnected. No key compromise, stake majority, or social engineering is required. The TODO comment at line 1841 confirms the developers are aware the check is wrong under Peras but have not yet corrected it.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` (the same `weights` value used in `constructPreferableCandidates` and `chainSelection`). The `weights` snapshot must be threaded into the ChainSync client's dynamic environment so that the disconnect guard and the chain selection engine use an identical comparison metric. Alternatively, if the intent is to remove the check entirely (as the TODO suggests), do so before Peras is activated on any production network.

---

### Proof of Concept

1. Activate Peras on a private testnet with boost weight B > 1.
2. Run an honest node whose current chain has N blocks and no boosted blocks (total weight = N).
3. Connect peer A (honest): serves a chain of N blocks where the tip carries a Peras boost → total weight = N + B.
4. Connect peer B (adversary): serves a chain of N+1 blocks with no boosts → total weight = N+1 < N+B.
5. Advance the honest node's chain to a slot beyond the forecast horizon so that `checkPreferTheirsOverOurs` is triggered for peer A.
6. Observe: `checkPreferTheirsOverOurs` evaluates `preferAnchoredCandidate … emptyPerasWeightSnapshot ourFrag theirFrag` for peer A → block count N == N → `ShouldNotSwitch` → node throws `CandidateTooSparse` and **disconnects peer A**.
7. Peer B (adversary) passes the same check (N+1 > N) and remains connected.
8. The node's actual chain selection, using real weights, would have preferred peer A's chain (N+B > N+1), but peer A is now gone.
9. The node is left with only peer B's lighter chain and cannot adopt the canonical chain. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L774-778)
```haskell
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1144)
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
 where
  ChainSelEnv{..} = chainSelEnv

  sortCandidates ::
    [(ChainDiff (Header blk), ReasonForSwitch' blk)] -> [(ChainDiff (Header blk), ReasonForSwitch' blk)]
  sortCandidates = sortBy ((flip $ compareChainDiffs bcfg weights curChain) `on` fst)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-203)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Fragment/Diff.hs (L77-98)
```haskell
rollbackExceedsSuffix ::
  forall b0 b1 b2.
  ( HasHeader b0
  , HasHeader b1
  , HasHeader b2
  , HeaderHash b0 ~ HeaderHash b1
  , HeaderHash b0 ~ HeaderHash b2
  ) =>
  PerasWeightSnapshot b0 ->
  -- | The chain @C@ the diff is applied to.
  AnchoredFragment b1 ->
  ChainDiff b2 ->
  Bool
rollbackExceedsSuffix weights curChain (ChainDiff nbRollback suffix) =
  weightOf suffixToRollBack > weightOf suffix
 where
  suffixToRollBack = AF.anchorNewest nbRollback curChain

  weightOf ::
    (HasHeader b, HeaderHash b ~ HeaderHash b0) =>
    AnchoredFragment b -> PerasWeight
  weightOf = totalWeightOfFragment weights
```
