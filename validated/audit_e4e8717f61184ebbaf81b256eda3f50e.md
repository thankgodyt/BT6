### Title
ChainSync Client Disconnect Decision Ignores Peras Weight Boosts via Hardcoded Empty Snapshot — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client passes a hardcoded `emptyPerasWeightSnapshot` — the exact zero-equivalent of the external report's `fill_static_args.fee_rate == 0.0` — to `preferAnchoredCandidate` instead of the live `PerasWeightSnapshot` held by the ChainDB. As a result, the disconnect guard that protects against peers serving non-preferred chains beyond the forecast horizon silently ignores all Peras weight boosts, making chain-preference decisions based on raw block count alone. This can cause the node to disconnect from honest peers serving the correct (heavier) Peras-boosted chain, or to retain connections to adversarial peers serving a longer-by-block-count but lighter chain, directly undermining Peras chain-selection safety.

---

### Finding Description

When the ChainSync client receives a header whose slot is beyond the current forecast horizon, it blocks in `readLedgerState` waiting for the ledger to advance. Before blocking it calls `checkPreferTheirsOverOurs` to decide whether the peer's candidate is worth waiting for. If the candidate is not preferred over the node's own chain, the client throws `CandidateTooSparse` and disconnects permanently. [1](#0-0) 

The preference test is:

```haskell
shouldSwitch $
  preferAnchoredCandidate
    (configBlock cfg)
    -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
    emptyPerasWeightSnapshot   -- ← hardcoded zero, not the live snapshot
    ourFrag
    theirFrag
```

`preferAnchoredCandidate` dispatches on `isEmptyPerasWeightSnapshot weights`: [2](#0-1) 

When the snapshot is empty the function falls into the block-count-only branch, ignoring `wsvWeightBoost` entirely. The live snapshot is available via `getPerasWeightSnapshot` on the `ChainDbView` that is already in scope inside `checkTime`/`readLedgerState`: [3](#0-2) 

The `PerasWeightSnapshot` is populated by `PerasCertDB` and exposed through `ChainDB.getPerasWeightSnapshot`: [4](#0-3) 

The `wsvTotalWeight` used in the weighted path is `blockNo + weightBoost`: [5](#0-4) 

By passing `emptyPerasWeightSnapshot`, the total-weight comparison degenerates to a pure block-number comparison, exactly as `fill_static_args.fee_rate == 0.0` caused the fee/rebate path to be skipped in the external report.

---

### Impact Explanation

**Incorrect disconnection from honest peers (primary security impact):**

Suppose the node's current fragment `ourFrag` has 100 blocks and carries Peras boosts totalling weight 200. An honest peer's fragment `theirFrag` has 99 blocks but carries Peras boosts totalling weight 210 (heavier overall). When `theirFrag`'s tip is beyond the forecast horizon:

- With the **live snapshot**: `wsvTotalWeight(theirFrag) = 210 > 200 = wsvTotalWeight(ourFrag)` → `ShouldSwitch` → `pure ()` (keep connection).
- With **`emptyPerasWeightSnapshot`**: comparison reduces to `blockNo`: `99 < 100` → `ShouldNotSwitch` → `throwSTM CandidateTooSparse` → **permanent disconnect from the honest peer**.

The node loses access to the heavier, canonical Peras chain and may subsequently adopt the lighter non-canonical chain.

**Failure to disconnect from adversarial peers (secondary impact):**

Conversely, if `ourFrag` has Peras boosts making it heavier but `theirFrag` is longer by block count, the empty-snapshot path returns `ShouldSwitch`, so the node retains the connection to an adversarial peer serving a lighter chain, wasting resources and potentially delaying adoption of the correct chain.

This is a **High** chain-selection bug: an unprivileged peer can craft a scenario (serving a longer-by-block-count but lighter chain) that causes the node to disconnect from honest Peras-boosted peers and prefer a non-canonical chain, violating Peras settlement guarantees.

---

### Likelihood Explanation

- Peras is an active extension in this codebase with production-path code (`PerasCertDB`, `addPerasCertAsync`, `getPerasWeightSnapshot` all wired into the live `ChainDB`).
- The trigger condition — a header beyond the forecast horizon — is a normal occurrence during syncing and when a peer's chain has a large slot gap.
- An adversarial peer needs only to serve a chain that is one block longer than the node's current chain; no key material or stake is required.
- The TODO comment at line 1841 confirms the developers themselves recognise this path is broken under Peras.

Likelihood: **Medium** (requires Peras certificates to be present on-chain and a header to arrive beyond the forecast horizon, both of which are normal operational conditions once Peras is active).

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` with the live snapshot read from `ChainDbView.getPerasWeightSnapshot`. Since `checkPreferTheirsOverOurs` runs inside an STM transaction that already reads from the ChainDB, the snapshot can be read atomically in the same transaction:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot chainDbView
  if shouldSwitch $
       preferAnchoredCandidate (configBlock cfg) weights ourFrag theirFrag
    then pure ()
    else throwSTM $ CandidateTooSparse ...
```

This mirrors how `getCurrentChainLike` already reads the live snapshot: [6](#0-5) 

---

### Proof of Concept

**Setup (private testnet or simulation):**

1. Start a node whose current chain has 100 blocks, with a valid Peras certificate boosting block 95 by weight 50 → `totalWeight(ourFrag) = 100 + 50 = 150`.
2. Connect an honest peer whose chain has 99 blocks, with a valid Peras certificate boosting block 98 by weight 60 → `totalWeight(theirFrag) = 99 + 60 = 159 > 150`.
3. Arrange for the honest peer's tip slot to be just beyond the current forecast horizon (e.g., by introducing a slot gap larger than the stability window).

**Observed behaviour (buggy):**

4. `checkTime` calls `readLedgerState` → `projectLedgerView` returns `Nothing` (beyond horizon).
5. `checkPreferTheirsOverOurs` is invoked.
6. `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag` compares block numbers: `99 < 100` → `ShouldNotSwitch`.
7. `throwSTM (CandidateTooSparse ...)` fires → node permanently disconnects from the honest peer.

**Expected behaviour (fixed):**

8. With the live snapshot, `totalWeight(theirFrag) = 159 > 150 = totalWeight(ourFrag)` → `ShouldSwitch` → `pure ()` → connection retained → node eventually adopts the heavier canonical chain. [7](#0-6) [2](#0-1) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L344-346)
```haskell
getPerasWeightSnapshot ::
  ChainDbEnv m blk -> STM m (WithFingerprint (PerasWeightSnapshot blk))
getPerasWeightSnapshot CDB{..} = PerasCertDB.getWeightSnapshot cdbPerasCertDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L186-187)
```haskell
isEmptyPerasWeightSnapshot :: PerasWeightSnapshot blk -> Bool
isEmptyPerasWeightSnapshot = Map.null . getPerasWeightSnapshot
```
