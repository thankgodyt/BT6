### Title
Peras Weight Snapshot Omitted in ChainSync `checkPreferTheirsOverOurs` Enables Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client unconditionally passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate` when evaluating whether a peer's chain (beyond the forecast horizon) is preferable to the node's current selection. This is the direct analog of the external report's `totalAssets()` bug: a "total weight" calculation that silently omits a category of state (Peras certificate boosts) that is present elsewhere in the system, corrupting the decision that depends on it.

---

### Finding Description

In `Ouroboros.Consensus.MiniProtocol.ChainSync.Client`, when a received header is beyond the forecast horizon, the client calls `checkPreferTheirsOverOurs` to decide whether to continue syncing or throw `CandidateTooSparse` (disconnect):

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty; actual snapshot ignored
        ourFrag
        theirFrag =
    pure ()
  | otherwise =
    throwSTM $
      CandidateTooSparse ...
```

The actual Peras weight snapshot is available in the same STM context via `getPerasWeightSnapshot` (backed by `PerasCertDB.getWeightSnapshot`), which reads `pcdsCertsByTicket` and computes the live `PerasWeightSnapshot`. That snapshot is used correctly everywhere else in chain selection:

- `chainSelectionForBlock` reads it atomically before every candidate evaluation.
- `constructPreferableCandidates` and `chainSelection` both receive and apply it.
- `rollbackExceedsSuffix` and `preferAnchoredCandidate` (in all other call sites) receive the real snapshot.

Only `checkPreferTheirsOverOurs` substitutes `emptyPerasWeightSnapshot`, making the comparison block-count-only and blind to all Peras certificate boosts.

---

### Impact Explanation

**Chain selection error — High.**

`preferAnchoredCandidate` with `emptyPerasWeightSnapshot` reduces to a pure block-count comparison. Under Peras, a chain with fewer blocks but sufficient certificate boosts can have strictly greater total weight (`wsvTotalWeight = blockNo + weightBoost`) and be the canonical chain. The empty-snapshot comparison inverts the preference:

- A peer offering a Peras-boosted chain that is shorter in block count than the node's current selection will fail the `shouldSwitch` test → the node throws `CandidateTooSparse` and disconnects from that peer.
- A peer offering a longer-in-blocks but unboosted (or less-boosted) chain will pass the test → the node continues syncing and may adopt that chain.

Concrete attack path:

1. Attacker serves a chain `C_adv` with `N+1` blocks and zero Peras boosts.
2. Honest peers serve chain `C_hon` with `N` blocks and Peras boosts totalling `> 1` weight unit (so `C_hon` is heavier).
3. Both chains are beyond the victim's forecast horizon (realistic during initial sync or after a partition).
4. For `C_adv`: `preferAnchoredCandidate cfg emptySnap ourFrag C_adv` → `ShouldSwitch` (more blocks) → node continues syncing with attacker.
5. For `C_hon`: `preferAnchoredCandidate cfg emptySnap ourFrag C_hon` → `ShouldNotSwitch` (fewer blocks, boost ignored) → node disconnects from honest peers.
6. Node adopts `C_adv` (the less-secure chain) and has no remaining connection to `C_hon`.

The node now permanently prefers the non-canonical chain. Subsequent chain selection within `chainSelectionForBlock` uses the real snapshot, but because the node has severed connections to honest peers, it never receives `C_hon`'s headers to compare against.

---

### Likelihood Explanation

**Low.** The attacker must:
- Be a peer of the victim during a sync window where headers are beyond the forecast horizon (initial sync, post-partition recovery).
- Produce a chain longer in block count than the honest chain at that moment.
- Ensure honest peers' chains are shorter in block count (but heavier via Peras boosts).

This is a realistic but non-trivial setup. It does not require key compromise, stake majority, or admin access — only a crafted chain served over the standard ChainSync mini-protocol.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot obtained from `getPerasWeightSnapshot cdb` (or the equivalent STM read already available in the ChainSync client's environment). The existing TODO comment (`https://github.com/tweag/cardano-peras/issues/64`) acknowledges the problem; the fix is to pass the real snapshot rather than removing the check entirely, until the Genesis-related density check can be redesigned to be Peras-aware.

---

### Proof of Concept

```
Victim node V, attacker A, honest peer H.

V's current chain:  [G ... B_k]          (k blocks, Peras boost = 0)
A's chain:          [G ... B_k ... B_k+1] (k+1 blocks, Peras boost = 0)
H's chain:          [G ... B_k']          (k blocks, Peras boost = W > 1)

All three chains share the same anchor; H's chain diverges at some point
after the forecast horizon.

Step 1: V receives header B_k+1 from A (beyond forecast horizon).
  checkPreferTheirsOverOurs: preferAnchoredCandidate emptySnap V A
    → ShouldSwitch (A has more blocks) → V continues syncing with A.

Step 2: V receives header B_k' from H (beyond forecast horizon).
  checkPreferTheirsOverOurs: preferAnchoredCandidate emptySnap V H
    → ShouldNotSwitch (H has same/fewer blocks, boost W ignored)
    → V throws CandidateTooSparse, disconnects from H.

Step 3: V adopts A's chain (k+1 blocks, weight = k+1).
         H's chain has weight = k + W > k+1 (for W > 1), but V never sees it.

Result: V is permanently on the less-secure chain C_adv.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L344-346)
```haskell
getPerasWeightSnapshot ::
  ChainDbEnv m blk -> STM m (WithFingerprint (PerasWeightSnapshot blk))
getPerasWeightSnapshot CDB{..} = PerasCertDB.getWeightSnapshot cdbPerasCertDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

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
