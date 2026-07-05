### Title
`checkPreferTheirsOverOurs` Uses `emptyPerasWeightSnapshot` While Actual Chain Selection Uses Real Peras Weights, Causing Incorrect Peer Disconnection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client evaluates whether a candidate chain is preferable using `emptyPerasWeightSnapshot` (no Peras boost weights), while the actual chain selection pipeline (`constructPreferableCandidates`, `chainSelection`) uses the real, live `PerasWeightSnapshot`. When Peras is active and a peer offers a Peras-boosted candidate chain of equal block-count to the local chain, the predicate incorrectly concludes the candidate is not preferable and throws `CandidateTooSparse`, disconnecting from the peer. The actual chain selection would have accepted and adopted that chain. The codebase itself acknowledges this with a `TODO` comment pointing to an open issue.

---

### Finding Description

`checkPreferTheirsOverOurs` is called inside `readLedgerStateHelper` whenever `projectLedgerView` returns `Nothing` — i.e., the incoming header's slot is beyond the current forecast horizon. Its purpose is to avoid blocking indefinitely waiting for the forecast horizon to advance for a candidate chain that would never be adopted anyway.

The check is:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, ignores Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` branches on whether the weight snapshot is empty:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- simple block-count comparison only
  | otherwise =
      -- uses Peras boost weights for comparison
``` [2](#0-1) 

By contrast, the actual chain selection in `constructPreferableCandidates` passes the real `weights`:

```haskell
ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
``` [3](#0-2) 

And `chainSelection` asserts the same real weights:

```haskell
assert
  ( all
      (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
      chainDiffs
  )
``` [4](#0-3) 

The `emptyPerasWeightSnapshot` is defined as a map with no entries, causing `isEmptyPerasWeightSnapshot` to return `True` and bypassing all Peras boost logic: [5](#0-4) 

---

### Impact Explanation

When Peras is active and a peer presents a candidate chain of the **same block count** as the local chain but with **Peras boost weight** (i.e., one or more blocks on the candidate have been certified by Peras):

1. The candidate header arrives beyond the forecast horizon → `projectLedgerView` returns `Nothing`.
2. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs`.
3. The check evaluates `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag` → `ShouldNotSwitch` (chains are equal length, no boost counted).
4. `throwSTM CandidateTooSparse` fires → the node disconnects from the peer.
5. The actual chain selection, had it been reached, would have used real Peras weights and returned `ShouldSwitch`.

The node permanently discards a valid, Peras-preferred chain and remains on the non-boosted fork. This is a **chain selection error**: the node prefers a non-canonical chain over the Peras-canonical chain, which is precisely the safety property Peras is designed to enforce.

**Impact class:** High — chain selection bug that causes an honest node to prefer a non-canonical chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

The conditions required are:

- Peras is active and has issued at least one certificate boosting a block on a competing fork (realistic once Peras is deployed on mainnet).
- The competing fork has the same block count as the local chain (common during temporary forks or when two leaders produce blocks in the same slot).
- The competing fork's tip slot is beyond the current forecast horizon at the intersection point (occurs naturally when the fork diverged more than one stability window ago, or during initial sync).

All three conditions can arise from normal network operation without any adversarial action. The `TODO` comment in the source code explicitly acknowledges the problem and links to an open issue, confirming the developers consider this a real defect.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the actual live `PerasWeightSnapshot` from the `ChainDB` (the same snapshot used by `constructPreferableCandidates` and `chainSelection`). The `ChainSyncStateView` or `DynamicEnv` would need to expose the current weight snapshot, or the check should be removed entirely as the TODO suggests (since the check is a heuristic optimisation, not a correctness requirement — the node can safely block waiting for the forecast horizon to advance for a genuinely preferable candidate).

---

### Proof of Concept

**Setup (private testnet or simulation):**

1. Enable Peras with a non-zero boost weight.
2. Create two forks diverging at block C (more than one stability window ago):
   - Local chain: `genesis → … → C → D → E` (block count = N, no Peras cert).
   - Peer chain: `genesis → … → C → F → G` (block count = N, Peras cert on F).
3. Connect the peer to the local node.
4. Arrange for the peer to send header G when G's slot is beyond the local forecast horizon (i.e., the intersection at C is older than one stability window).

**Expected (correct) behaviour:** The node blocks waiting for the forecast horizon to advance, then validates G, runs chain selection with real Peras weights, finds `ShouldSwitch`, and adopts the peer's chain.

**Actual (buggy) behaviour:** `checkPreferTheirsOverOurs` evaluates `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag`. Since both fragments have the same block count and no boost is counted, it returns `ShouldNotSwitch EQ`. The node throws `CandidateTooSparse` and disconnects from the peer. The local node remains on the non-Peras-canonical fork indefinitely. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1821-1857)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L774-778)
```haskell
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1132)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L56-57)
```haskell
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
