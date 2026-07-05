### Title
Stale (Empty) Peras Weight Snapshot Used in ChainSync Candidate Comparison Beyond Forecast Horizon - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when comparing a peer's candidate chain against the local chain at the point where the ledger view cannot be forecast. This means Peras weight boosts are completely ignored in that comparison. A peer whose chain is heavier by Peras weight but shorter by block count will be incorrectly disconnected with `CandidateTooSparse`, causing the honest node to fail to adopt the canonical (heavier) chain.

---

### Finding Description

When the ChainSync client receives a header whose slot is beyond the forecast horizon, it cannot obtain a `LedgerView` to validate the header. Before blocking to wait for the local chain to advance, it calls `checkPreferTheirsOverOurs` to decide whether to keep the connection open or disconnect:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, ignores all Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` has two code paths: when the snapshot is empty it falls back to a pure block-count comparison; when it is non-empty it uses the full weighted comparison:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- block-count / tiebreaker only
  | otherwise =
      -- weighted comparison using Peras boosts
``` [2](#0-1) 

The actual live weight snapshot is available via `getPerasWeightSnapshot` on the `ChainDB`, which reads from `PerasCertDB`:

```haskell
getPerasWeightSnapshot CDB{..} = PerasCertDB.getWeightSnapshot cdbPerasCertDB
``` [3](#0-2) 

`implGetWeightSnapshot` builds the snapshot from all stored certificates:

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds) ]
  pure (WithFingerprint weights fp)
``` [4](#0-3) 

Every other call site in `ChainSel` correctly reads the live snapshot from the `TVar`:

```haskell
<*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [5](#0-4) 

Only `checkPreferTheirsOverOurs` substitutes the live snapshot with the hardcoded empty one.

---

### Impact Explanation

Consider the following scenario on a Peras-enabled network:

- **Our chain**: `A → B → C → D` (4 blocks, no Peras boosts, total weight = 4)
- **Peer's chain**: `A → B → E` (3 blocks, block `E` carries a Peras boost of 2, total weight = 5)

The peer's chain is the canonical chain (heavier). The peer's tip is beyond our forecast horizon.

With `emptyPerasWeightSnapshot`: peer has 3 blocks < our 4 → `shouldSwitch` = false → node throws `CandidateTooSparse` and disconnects.

With the actual weight snapshot: peer has total weight 5 > our weight 4 → `shouldSwitch` = true → node keeps the connection and eventually adopts the canonical chain.

The node is permanently prevented from adopting the canonical chain via this peer. This is a chain-selection bug: an honest node is made to prefer a non-canonical (lighter) chain over the canonical (heavier) one, triggered by any unprivileged peer whose chain is beyond the forecast horizon.

---

### Likelihood Explanation

The conditions required are:

1. Peras is active (certificates are being produced and boosting blocks).
2. A peer's chain tip is beyond the local node's forecast horizon (common during syncing, after a restart, or after a large slot gap).
3. The peer's chain is heavier by Peras weight but shorter by block count relative to the local chain.

Condition 2 is routine during normal node operation. Conditions 1 and 3 become routine once Peras is deployed. No privileged access, key compromise, or stake majority is required. Any peer can trigger this path simply by advertising a chain whose tip is beyond the forecast horizon.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read from the `ChainDB`, consistent with every other call site in `ChainSel`:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot  -- read live snapshot
  if shouldSwitch $
       preferAnchoredCandidate (configBlock cfg) weights ourFrag theirFrag
    then pure ()
    else throwSTM $ CandidateTooSparse ...
```

The linked issue (`https://github.com/tweag/cardano-peras/issues/64`) proposes removing the check entirely; until that is done, the snapshot must not be hardcoded to empty.

---

### Proof of Concept

**Setup** (private testnet with Peras enabled):

1. Node N holds chain `A → B → C → D` (4 blocks, no Peras boosts).
2. A Peras certificate is issued boosting block `E` (on a fork `A → B → E`) with boost weight 2, making `E`'s chain total weight = 5 > 4.
3. Peer P advertises chain `A → B → E`. The tip slot of `E` is beyond N's forecast horizon (e.g., N has been offline or there is a large slot gap).
4. N calls `checkPreferTheirsOverOurs` with `emptyPerasWeightSnapshot`.
5. `preferAnchoredCandidate` compares 3 blocks (peer) vs 4 blocks (ours) → `ShouldNotSwitch`.
6. N throws `CandidateTooSparse` and disconnects from P.
7. N never adopts the canonical chain `A → B → E`.

**Expected behaviour** (with fix): step 4 uses the live snapshot containing the boost for `E`; `preferAnchoredCandidate` returns `ShouldSwitch`; N keeps the connection and eventually adopts the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L631-634)
```haskell
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```
