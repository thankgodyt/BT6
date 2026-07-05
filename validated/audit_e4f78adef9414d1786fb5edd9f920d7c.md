### Title
ChainSync Client `checkPreferTheirsOverOurs` Ignores Peras Certificate Weights, Enabling Chain Selection Failure - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` guard in the ChainSync client is called when a peer's header is beyond the forecast horizon. It is supposed to disconnect peers whose chains are no longer preferable to ours. However, it unconditionally passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate` instead of the real Peras weight snapshot, meaning it compares chains purely by block count and ignores all Peras certificate boosts. This is structurally identical to the external report's pattern: a guard function that should enforce a state-transition invariant is missing the critical check — here, the missing check is the Peras weight — causing the node to incorrectly disconnect from peers serving the canonical (heavier) chain and remain on a lighter, potentially adversarial chain.

---

### Finding Description

In `Ouroboros.Consensus.MiniProtocol.ChainSync.Client`, the function `readLedgerStateHelper` blocks waiting for the forecast horizon to advance. While waiting, it calls `checkPreferTheirsOverOurs` on every STM retry to verify the peer's chain is still preferable to ours. If the check fails, the peer is disconnected with `CandidateTooSparse`. [1](#0-0) 

The guard itself: [2](#0-1) 

The critical defect is at line 1841–1842:

```haskell
preferAnchoredCandidate
  (configBlock cfg)
  -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
  emptyPerasWeightSnapshot   -- ← always zero; real weights never consulted
  ourFrag
  theirFrag
```

`preferAnchoredCandidate` short-circuits to a pure block-count comparison whenever the weight snapshot is empty: [3](#0-2) 

So the guard never sees Peras certificate boosts. The real chain selection in `chainSelectionForBlock` and `chainSelection` does use the live `PerasWeightSnapshot` read from `cdbPerasWeightSnapshot`: [4](#0-3) 

There is therefore a split: the main chain-selection path correctly accounts for Peras weights, but the ChainSync client's forecast-horizon guard does not. The two paths can reach opposite conclusions about which chain is preferable.

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical, less-secure chain.**

Concrete scenario:

1. An adversary pre-seeds the target node with chain **A** (block count N, no Peras boost, total weight W). Chain A is longer in block count than the canonical chain, so the node adopts it via normal chain selection.
2. The canonical chain **B** (block count N−k, Peras-boosted total weight W + Δ > W) is later produced. A peer begins serving B's headers.
3. B's tip slot is beyond the forecast horizon relative to the intersection with A. The ChainSync client enters the `retry` loop and calls `checkPreferTheirsOverOurs`.
4. With `emptyPerasWeightSnapshot`, `preferAnchoredCandidate` compares N vs N−k blocks and concludes A is better. The peer is disconnected with `CandidateTooSparse`.
5. The node remains on chain A — the lighter, adversary-extended chain — and never adopts the canonical, Peras-boosted chain B.

The node has been made to prefer a non-canonical chain by an unprivileged peer, violating the Peras chain-selection invariant.

---

### Likelihood Explanation

**Medium.** The preconditions are:

- Peras is active on the network (the feature is implemented and being integrated).
- A Peras certificate exists that boosts a chain tip that is behind the current node tip in block count but ahead in total weight.
- The boosted chain's next header falls beyond the forecast horizon at the moment the ChainSync client processes it.

All three conditions are reachable in normal Peras operation. The adversary's only requirement is to have served a longer-by-block-count chain to the target node before the Peras certificate was issued — no stake majority, no key compromise, no privileged access.

The developers have already acknowledged the defect via the inline TODO comment referencing `cardano-peras#64`, confirming the check is known to be incorrect.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` read from the ChainDB (the same snapshot used by `chainSelectionForBlock`). This makes the guard consistent with the main chain-selection logic. Alternatively, remove the check entirely as the TODO proposes — the check's purpose (avoid waiting forever for a chain that will never be adopted) is already served by the Genesis Density Disconnection component for syncing nodes, and by the LoP bucket for caught-up nodes.

---

### Proof of Concept

```
Node state:
  ourFrag  = chain A, 100 blocks, no Peras boost, total weight = 100
  theirFrag = chain B, 98 blocks, Peras boost = 5, total weight = 103

Header H (tip of B) is at slot beyond forecast horizon.
checkPreferTheirsOverOurs is called.

  preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag
  → isEmptyPerasWeightSnapshot emptyPerasWeightSnapshot = True
  → compare selectView(ourTip) selectView(theirTip)
  → compare blockNo 100 blockNo 98
  → ShouldNotSwitch GT          ← wrong: real weight is 103 > 100

  → throwSTM CandidateTooSparse  ← peer disconnected

Node stays on chain A (weight 100) instead of switching to chain B (weight 103).
``` [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1817)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1081-1101)
```haskell
  Maybe (RealPoint blk, InvalidBlockPunishment m) ->
  ChainSelEnv m blk
mkChainSelEnv CDB{..} blockCache weights curChain punish =
  ChainSelEnv
    { lgrDB = cdbLedgerDB
    , bcfg = configBlock cdbTopLevelConfig
    , varInvalid = cdbInvalid
    , varTentativeState = cdbTentativeState
    , varTentativeHeader = cdbTentativeHeader
    , getTentativeFollowers =
        filter ((TentativeChain ==) . fhChainType) . Map.elems
          <$> readTVar cdbFollowers
    , blockCache
    , weights
    , curChain
    , validationTracer =
        TraceAddBlockEvent . AddBlockValidation >$< cdbTracer
    , pipeliningTracer =
        TraceAddBlockEvent . PipeliningEvent >$< cdbTracer
    , punish
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
