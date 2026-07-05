### Title
Hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` Causes Incorrect Chain-Preference Decision Beyond Forecast Horizon — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` helper inside the ChainSync client uses a hardcoded `emptyPerasWeightSnapshot` (an all-zero Peras weight map) when deciding whether to disconnect from a peer whose header is beyond the current forecast horizon. This is the direct analog of the external report's stale-cached-value bug: just as `zkusdAmounts[_token]` fails to reflect current token prices and therefore misjudges the rebalancing direction, `emptyPerasWeightSnapshot` fails to reflect actual Peras certificate boosts and therefore misjudges which chain is heavier. When Peras is active, the comparison can produce the wrong direction, causing the node to disconnect from a peer that is serving the canonical, Peras-boosted chain.

---

### Finding Description

In `readLedgerStateHelper`, when `projectLedgerView` returns `Nothing` (the incoming header is beyond the forecast horizon), the client calls `checkPreferTheirsOverOurs` to decide whether to keep waiting or to disconnect:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/
-- Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs  ~line 1834
checkPreferTheirsOverOurs kis
    | shouldSwitch $
        preferAnchoredCandidate
          (configBlock cfg)
          emptyPerasWeightSnapshot   -- ← hardcoded zero-weight snapshot
          ourFrag
          theirFrag =
        pure ()                      -- stay connected, keep waiting
    | otherwise =
        throwSTM $
          CandidateTooSparse ...     -- disconnect
```

`emptyPerasWeightSnapshot` is defined as `PerasWeightSnapshot Map.empty` — a map with no entries, giving every block a Peras boost of zero. The comparison therefore reduces to a raw-block-count comparison, identical to the pre-Peras code path.

The developer comment immediately above the call acknowledges the problem:

```haskell
-- TODO: remove this entire check,
-- see https://github.com/tweag/cardano-peras/issues/64
emptyPerasWeightSnapshot
```

`preferAnchoredCandidate` has two branches:

```haskell
-- Ouroboros/Consensus/Util/AnchoredFragment.hs ~line 186
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- fast path: compare only by raw block count / selectView
      ...
  | otherwise =
      -- Peras path: compute weighted suffix and compare
      ...
```

Because `isEmptyPerasWeightSnapshot emptyPerasWeightSnapshot` is always `True`, the Peras-weighted path is never reached inside `checkPreferTheirsOverOurs`, regardless of how many Peras certificates exist on either chain.

**Dangerous scenario (wrong direction):**

| Chain | Raw blocks | Peras-boosted weight |
|-------|-----------|----------------------|
| `ourFrag` | N | W_ours (large, many certs) |
| `theirFrag` | M < N | W_theirs > W_ours |

With `emptyPerasWeightSnapshot`, `preferAnchoredCandidate` sees only raw block counts: M < N → `ShouldNotSwitch` → `throwSTM CandidateTooSparse` → **disconnect from the peer serving the heavier, canonical chain**.

The node then remains on its own lighter chain and never adopts the canonical Peras-boosted chain.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

Once Peras is active, a node that has accumulated Peras certificates on its own chain can be made to disconnect from every honest peer whose candidate header happens to arrive beyond the current forecast horizon, if those peers' chains are heavier only because of Peras boosts (not raw block count). The node then stays on a chain that is lighter by the Peras metric, which is precisely the chain the Peras protocol is designed to make canonical. This is a chain-selection inversion: the node prefers the non-canonical chain.

---

### Likelihood Explanation

**Low today, but structurally certain once Peras is deployed.** The code is already in production. The trigger condition — a header arriving beyond the forecast horizon — is a normal occurrence during syncing and when a peer's chain has a slot gap larger than the forecast window. No special privileges, keys, or stake are required from the attacker; any peer can send a header that is beyond the local forecast horizon. The only prerequisite is that Peras certificates exist on the network, which is the intended steady state after Peras activation.

---

### Recommendation

The TODO comment already points to the correct fix: remove `checkPreferTheirsOverOurs` entirely (per the linked issue). If the check must be retained for Genesis-related reasons, it must be supplied with the actual live `PerasWeightSnapshot` from the ChainDB (the same `weights` value used in `ChainSel.hs`), not the hardcoded empty snapshot. The `ConfigEnv` or `DynamicEnv` passed to `checkTime` should carry the current snapshot so that `checkPreferTheirsOverOurs` can use it.

---

### Proof of Concept

1. Peras is active; the network has issued certificates boosting blocks on the canonical chain.
2. The local node's `ourFrag` has N raw blocks and a large Peras-boosted weight W_ours.
3. An honest peer's `theirFrag` has M < N raw blocks but Peras-boosted weight W_theirs > W_ours (the canonical chain is heavier by the Peras metric).
4. The peer sends a header whose slot is beyond the local forecast horizon (e.g., a slot gap larger than the forecast window, which is normal during initial sync).
5. `rollForward` → `checkTime` → `checkArrivalTime` → `readLedgerStateHelper` → `projectLedgerView` returns `Nothing`.
6. `checkPreferTheirsOverOurs` is called with `emptyPerasWeightSnapshot`.
7. `preferAnchoredCandidate` takes the fast path (empty weights), compares raw block counts: M < N → `ShouldNotSwitch`.
8. `throwSTM CandidateTooSparse` fires; the node disconnects from the honest peer.
9. The node never adopts the canonical Peras-boosted chain; it remains on the lighter, non-canonical chain.

**Root cause lines:** [1](#0-0) 

**`emptyPerasWeightSnapshot` definition (the stale/zero value):** [2](#0-1) 

**`preferAnchoredCandidate` branching on empty vs. real weights:** [3](#0-2) 

**`readLedgerStateHelper` calling `checkPreferTheirsOverOurs` on forecast miss:** [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1794-1819)
```haskell
  readLedgerStateHelper kis prj = atomically $ do
    -- We must first find the most recent intersection with the current
    -- chain. Note that this is cheap when the chain and candidate haven't
    -- changed.
    intersectsWithCurrentChain kis >>= \case
      NoLongerIntersects -> return exitEarly
      StillIntersects () kis' -> do
        let KnownIntersectionState
              { mostRecentIntersection
              } = kis'
        lst <-
          fmap
            ( maybe
                ( error $
                    "intersection not within last k blocks: "
                      <> show mostRecentIntersection
                )
                ledgerState
            )
            $ getPastLedger mostRecentIntersection
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
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
