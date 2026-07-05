### Title
Peras Weight Ignored in `checkPreferTheirsOverOurs` Causes Chain Selection Error When Peras Is Enabled — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When Peras is enabled, the `checkPreferTheirsOverOurs` function in the ChainSync client hardcodes `emptyPerasWeightSnapshot` instead of using the live Peras weight snapshot. This causes the node to evaluate chain preference using block count alone, ignoring certificate-derived weight boosts. As a result, the node may disconnect from peers serving the canonical (heavier but shorter) chain and remain on a lighter, non-canonical fork — a chain selection error reachable by any unprivileged peer.

---

### Finding Description

`checkPreferTheirsOverOurs` is invoked when a received header is beyond the forecast horizon and the node must decide whether to keep waiting (candidate is preferred) or disconnect (our chain is preferred). [1](#0-0) 

The call to `preferAnchoredCandidate` is made with a hardcoded `emptyPerasWeightSnapshot`:

```haskell
preferAnchoredCandidate
  (configBlock cfg)
  -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
  emptyPerasWeightSnapshot
  ourFrag
  theirFrag
```

When `isEmptyPerasWeightSnapshot weights` is `True`, `preferAnchoredCandidate` falls into the non-Peras branch and compares chains purely by `selectView` (block number + VRF tiebreaker), ignoring all Peras certificate boosts: [2](#0-1) 

By contrast, when Peras is active, the correct comparison must use `weightedSelectView`, which sums block number and `wsvWeightBoost` (the accumulated certificate weight for the fragment suffix after the intersection): [3](#0-2) 

The `PerasCertDB` continuously accumulates certificate boosts via `implGetWeightSnapshot`, which derives the live `PerasWeightSnapshot` from all stored `ValidatedPerasCert` entries: [4](#0-3) 

These live weights are used correctly everywhere else in chain selection (e.g., `constructPreferableCandidates`, `chainSelection`): [5](#0-4) 

But `checkPreferTheirsOverOurs` is the one site that bypasses them entirely.

The analog to the Splitter dilution pattern is direct: Peras certificates are the "new shares" that retroactively increase the weight of already-committed blocks. The `checkPreferTheirsOverOurs` check ignores these new shares when evaluating whether the candidate is preferred, so a chain that has been legitimately boosted by certificates appears lighter than it is — exactly as existing shareholders are diluted when new payees are added to unclaimed funds.

---

### Impact Explanation

When Peras is enabled and the canonical chain has received certificate boosts making it heavier (in total Peras weight) but shorter (in block count) than a competing fork:

1. A peer serving the canonical chain sends a header beyond the forecast horizon.
2. `checkPreferTheirsOverOurs` compares by block count only → canonical chain appears not preferred → **node disconnects from the honest peer**.
3. Simultaneously, a peer serving the longer-but-lighter fork is kept alive (its chain appears preferred by block count).
4. The node remains on the non-canonical, lighter fork.

If the node disconnects from all honest peers serving the canonical chain before the forecast horizon advances, it may be permanently isolated on the wrong chain. This is a chain selection error that lets an unprivileged peer cause an honest node to prefer a non-canonical, less-secure chain — matching the **High** impact tier.

---

### Likelihood Explanation

**Low-medium.** Peras is currently disabled by default (the `emptyPerasWeightSnapshot` fast-path in `compareAnchoredFragments` and `preferAnchoredCandidate` is a no-op today). The bug activates only when Peras is enabled and a header arrives beyond the forecast horizon while the canonical chain has accumulated certificate weight exceeding its block-count lead. The developers have already acknowledged the issue via the TODO comment referencing issue #64, which proposes removing the check entirely when Peras is active. The condition is realistic in any Peras-enabled private testnet or future mainnet deployment.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live weight snapshot read from `PerasCertDB.getWeightSnapshot`. Alternatively, as the TODO comment suggests, remove the check entirely when Peras is enabled, since Peras breaks the monotonicity assumption (longer chain ≡ heavier chain) that the check relies on. The correct Peras-aware comparison is already implemented in `preferAnchoredCandidate` for the non-empty-snapshot branch and should be reused here.

---

### Proof of Concept

Private-testnet sequence (Peras enabled):

1. Produce chain **C** (canonical): 100 blocks, receives 3 Peras certificate boosts → total weight = 100 + 3×B (where B is the configured boost weight, e.g. 15 → total weight 145).
2. Produce fork **F** (adversarial): 110 blocks, no certificates → total weight = 110.
3. Connect the target node to peer **P_F** serving fork F and peer **P_C** serving chain C.
4. Craft a header on F at a slot beyond the forecast horizon (> `stabilityWindow` slots ahead of the intersection). The ChainSync client calls `projectLedgerView`, which returns `Nothing`, triggering `checkPreferTheirsOverOurs`.
5. `checkPreferTheirsOverOurs` calls `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag_F`. Fork F has 110 blocks vs. our 100 → `ShouldSwitch` → node keeps waiting for F. ✓ (correct by block count, but F is lighter)
6. Repeat for a header on C beyond the forecast horizon. `checkPreferTheirsOverOurs` calls `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag_C`. Chain C has 100 blocks vs. our 100 → `ShouldNotSwitch` → **node disconnects from P_C**. ✗ (C is actually heavier: 145 > 110)
7. Node is now connected only to P_F. When the forecast horizon eventually advances, chain selection runs with real weights: F (110) < C (145), but P_C is gone. Node remains on F.

The root cause is the single line `emptyPerasWeightSnapshot` at: [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L774-778)
```haskell
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```
