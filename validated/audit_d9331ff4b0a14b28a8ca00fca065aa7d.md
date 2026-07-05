### Title
Incorrect Comparison Granularity in ChainSync Client Disconnection Check Causes Chain Selection Error When Peras Is Enabled — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When Peras is enabled, the ChainSync client's `checkPreferTheirsOverOurs` guard always evaluates candidate preference using `emptyPerasWeightSnapshot` (tip-only block-number comparison) instead of the live Peras weight snapshot (full-suffix weighted comparison). This is the direct analog of the futex bug: the wrong granularity of value is used for a consensus-critical comparison, causing the node to make incorrect chain-preference decisions.

---

### Finding Description

The futex vulnerability class is: **a comparison that should operate on a narrow/correct value instead operates on a wider/wrong value, producing an incorrect result that drives a synchronization decision**.

In Ouroboros Consensus the analog is in `checkPreferTheirsOverOurs`, called inside the ChainSync client when a received header is beyond the forecast horizon. The function must decide whether the candidate chain is preferred over the node's current selection; if not, it disconnects the peer with `CandidateTooSparse`.

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, ignores live Peras weights
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` has two distinct code paths depending on whether the weight snapshot is empty:

- **Empty snapshot (Peras disabled):** compares only the `SelectView` of the **tip** of each fragment — i.e., `(BlockNo, TiebreakerView)`.
- **Non-empty snapshot (Peras enabled):** finds the intersection of the two fragments, then compares `weightedSelectView` of the **full suffixes** after the intersection, summing all Peras boosts across every block in the suffix. [2](#0-1) 

The actual chain selection in `ChainDB` uses the live `weights` snapshot:

```haskell
-- ChainSel.hs
preferAnchoredCandidate bcfg weights curChain chain   -- live weights
``` [3](#0-2) 

The `wsvTotalWeight` used in the Peras path is `BlockNo + PerasWeightBoost` across the entire suffix:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

The weight boost is the sum of all Peras certificate boosts on every block in the fragment suffix: [5](#0-4) 

---

### Impact Explanation

When Peras is enabled, a peer can serve a candidate chain that is **heavier** (higher `wsvTotalWeight` due to Peras boosts) but **shorter** (lower tip `BlockNo`) than the node's current selection. Under the correct Peras-weighted comparison this chain is preferred; under the tip-only comparison used in `checkPreferTheirsOverOurs` it is not.

Consequence: `checkPreferTheirsOverOurs` fires `CandidateTooSparse` and disconnects the peer — even though that peer is serving the canonical, heavier chain. The node then remains on a lighter, non-canonical chain. This is a **chain selection error** matching the "High" impact tier: an unprivileged peer (or the absence of the correct peer) causes an honest node to prefer a non-canonical chain beyond the intended Peras security assumptions.

The inverse direction is also possible: a chain that is longer (higher `BlockNo`) but lighter (fewer or no Peras boosts) passes the `checkPreferTheirsOverOurs` guard, keeping the connection alive, while the actual ChainDB selection would correctly reject it as non-preferred. This is less severe but still a mismatch between the guard and the actual selection rule.

---

### Likelihood Explanation

**Low-to-medium** when Peras is enabled. Peras is disabled by default on production Cardano mainnet; the CHANGELOG explicitly states "if Peras is disabled (which is the default), there is no observable difference." However, the code path is fully compiled in and the feature flag can be enabled by operators. Once enabled, the condition is triggered whenever a ChainSync peer sends a header beyond the forecast horizon — a reachable condition any peer can induce by presenting a chain with a large slot gap. No key compromise, stake majority, or privileged access is required.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live Peras weight snapshot (the same `weights` value used in `ChainDB`'s `preferAnchoredCandidate` calls). The existing TODO comment at line 1841 already tracks this. Until fixed, the guard and the actual chain selection use different comparison granularities, violating the invariant that the ChainSync client's preference check must agree with ChainDB's selection rule.

---

### Proof of Concept

1. Enable Peras on a private testnet with a non-zero `PerasWeight` boost.
2. Arrange for a Peras certificate to boost a block `B` on a candidate chain `C_cand` such that `C_cand` has a lower tip `BlockNo` than the node's current chain `C_cur` but a higher `wsvTotalWeight` (i.e., `BlockNo(C_cand) + boost > BlockNo(C_cur)`).
3. Have a peer serve `C_cand` with a header beyond the forecast horizon.
4. Observe that `checkPreferTheirsOverOurs` evaluates `preferAnchoredCandidate ... emptyPerasWeightSnapshot`, finds `C_cand` not preferred (shorter tip), and throws `CandidateTooSparse`, disconnecting the peer.
5. Confirm that if the same `C_cand` were presented to `ChainDB`'s `chainSelection` with the live weight snapshot, it would be selected as preferred.
6. The node remains on `C_cur` (the lighter, non-canonical chain) despite `C_cand` being the correct canonical chain under Peras rules.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
