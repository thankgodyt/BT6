### Title
Stale Peras Weight Snapshot in `checkPreferTheirsOverOurs` Causes Incorrect Chain Selection Disconnect - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client uses a hardcoded `emptyPerasWeightSnapshot` instead of the live Peras weight snapshot from the ChainDB when deciding whether to disconnect from a peer whose headers are beyond the forecast horizon. This is structurally identical to the external report's pattern: a value is fixed at one point in the code path while the underlying state (Peras certificate boosts) can change, causing the gating decision to be made on stale/incorrect data.

### Finding Description

When a header from a peer is beyond the forecast horizon, `checkPreferTheirsOverOurs` is called to decide whether to keep waiting (their chain is preferable) or disconnect (`CandidateTooSparse`). The comparison is:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        emptyPerasWeightSnapshot   -- ← hardcoded empty, ignores all Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

The actual chain selection in `chainSelectionForBlock` and `chainSelSync` correctly reads the live snapshot:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [2](#0-1) 

`preferAnchoredCandidate` has two distinct code paths: when the snapshot is empty it falls back to pure block-count comparison; when non-empty it computes total weight including Peras boosts: [3](#0-2) 

`getPerasWeightSnapshot` is available as an STM action on the ChainDB and is the authoritative source of current Peras boosts: [4](#0-3) 

The developers acknowledge the problem with a TODO comment at the call site:

```
-- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
emptyPerasWeightSnapshot
``` [5](#0-4) 

### Impact Explanation

**Impact: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

When a candidate chain contains Peras-certified (boosted) blocks, the real total weight of that chain exceeds its raw block count. With `emptyPerasWeightSnapshot`, `preferAnchoredCandidate` compares only raw block counts. If the local chain is longer in raw blocks but the candidate chain is heavier in total Peras weight, the comparison returns `ShouldNotSwitch` (our chain appears better), causing the node to throw `CandidateTooSparse` and disconnect from the peer. The node then stays on its shorter-but-unboosted chain, which is less secure under the Peras security model. The actual chain selection code path (which uses the real snapshot) would have concluded the opposite — that the candidate is preferable — but it is never reached because the peer was already disconnected.

### Likelihood Explanation

**Likelihood: Low** — Requires Peras to be active on the network (certificates being produced), a candidate chain that has accumulated Peras boosts, and the candidate's headers to be beyond the local forecast horizon at the moment of the check. All three conditions must coincide. The scenario is realistic in a live Peras-enabled network but requires a specific timing alignment.

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read from the ChainDB, consistent with how `chainSelectionForBlock` and `chainSelSync` obtain it. Since `checkPreferTheirsOverOurs` already runs inside `atomically`, the snapshot can be read in the same STM transaction via `Query.getPerasWeightSnapshot`. Alternatively, if the check is to be removed entirely (as the TODO suggests), it should be removed before Peras is activated on mainnet to avoid the incorrect disconnection behaviour.

### Proof of Concept

1. Peras is active; a certificate boosts block `B` on a candidate chain `C` by weight `W`.
2. The local chain `L` has raw length `n`; candidate chain `C` has raw length `n-1` but total Peras weight `n-1+W > n`.
3. A peer sends a header from `C` that is beyond the local forecast horizon, triggering `checkPreferTheirsOverOurs`.
4. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag` compares raw block counts: `n` vs `n-1` → `ShouldNotSwitch`.
5. The node throws `CandidateTooSparse` and disconnects.
6. The same comparison with the real snapshot would yield total weights `n` vs `n-1+W` → `ShouldSwitch`, meaning the node should have kept waiting and eventually adopted `C`.
7. The node remains on the less-secure chain `L`. [1](#0-0) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L344-346)
```haskell
getPerasWeightSnapshot ::
  ChainDbEnv m blk -> STM m (WithFingerprint (PerasWeightSnapshot blk))
getPerasWeightSnapshot CDB{..} = PerasCertDB.getWeightSnapshot cdbPerasCertDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```
