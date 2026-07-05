### Title
Hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` Causes Incorrect Chain-Selection Disconnection When Peras Is Active — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client uses a hardcoded `emptyPerasWeightSnapshot` instead of the real Peras weight snapshot when deciding whether to disconnect from a peer whose candidate header is beyond the forecast horizon. This is the direct consensus analog of the reported vulnerability: the code uses the wrong function variant — one that ignores available state (Peras certificate boosts already held by the ChainDB) — causing incorrect chain-preference decisions. When Peras is active, a node can incorrectly disconnect from a peer offering the canonical Peras-boosted chain, leaving the node stranded on a non-canonical chain.

---

### Finding Description

When a peer's header is beyond the forecast horizon, the ChainSync client cannot yet validate it and enters a retry loop waiting for the local chain to advance. Before retrying, it calls `checkPreferTheirsOverOurs` to decide whether the peer's chain is even worth waiting for. If the peer's chain is judged not preferred over the node's current chain, the node disconnects with `CandidateTooSparse`.

The preference check is performed by `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot` argument. When Peras is active, this snapshot contains the certificate-derived weight boosts for blocks on the chain; a chain can be "heavier" (and therefore preferred) even if it is not strictly longer by block count.

However, `checkPreferTheirsOverOurs` always passes `emptyPerasWeightSnapshot` — a hardcoded empty map — to `preferAnchoredCandidate`:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, ignores real Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
```

With an empty snapshot, `preferAnchoredCandidate` falls into its fast path that compares chains purely by block count (length), ignoring all Peras weight boosts entirely:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- fast path: compare only by SelectView / block count
      ...
  | otherwise =
      -- Peras path: compare by weighted suffix
      ...
```

The real Peras weight snapshot is already maintained by the ChainDB and is correctly used elsewhere (e.g., in `NodeKernel.hs` via `ChainDB.getPerasWeightSnapshot chainDB`, and in `ChainSel.hs` via the `weights` field of `ChainSelEnv`). The ChainSync client simply never reads it.

**Root cause**: The code uses `emptyPerasWeightSnapshot` (the wrong variant — analogous to `safeTransferFrom` requiring an approval that is never set) instead of the real snapshot that the node already holds (analogous to calling `transfer` directly on the balance the contract already owns).

---

### Impact Explanation

When Peras is active and a peer offers a chain that is Peras-boosted (heavier by certificate weight) but not strictly longer by block count than the node's current chain:

1. The peer's header arrives beyond the forecast horizon.
2. `checkPreferTheirsOverOurs` is called.
3. With `emptyPerasWeightSnapshot`, `preferAnchoredCandidate` compares only by block count and concludes the peer's chain is **not** preferred.
4. The node disconnects from the peer with `CandidateTooSparse`.
5. The actual chain-selection logic in `ChainSel.hs` uses the real weights and **would** prefer the Peras-boosted chain — but the node has already disconnected from the only peer offering it.
6. The node remains on its current, non-canonical chain.

This is a **chain-selection bug**: an honest node is made to prefer (by staying on) a non-canonical chain because it incorrectly rejects the peer offering the canonical Peras-boosted chain. The disconnection is triggered by a crafted or naturally occurring network scenario — no operator compromise is required.

---

### Likelihood Explanation

The scenario requires:
- Peras to be active (certificates being issued on-chain), and
- A peer offering a Peras-boosted chain whose header is beyond the local forecast horizon (a normal occurrence during chain sync when the node is slightly behind).

Both conditions are routine in a Peras-enabled Cardano network. The bug is deterministic: every time the conditions are met, the node will incorrectly disconnect.

---

### Recommendation

Pass the real Peras weight snapshot to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`. The ChainDB already exposes `getPerasWeightSnapshot` (an STM action), and the ChainSync client has access to the ChainDB environment. The fix mirrors what `NodeKernel.hs` already does for the GSM's `getCandidateOverSelection`:

```haskell
-- NodeKernel.hs (correct usage for reference)
weights <- ChainDB.getPerasWeightSnapshot chainDB
preferAnchoredCandidate (configBlock cfg) (forgetFingerprint weights) headers (csCandidate state)
```

The same pattern should be applied in `checkPreferTheirsOverOurs`. The existing TODO comment (`-- TODO: remove this entire check`) indicates the developers intend to remove the check entirely; until that happens, the empty snapshot must be replaced with the real one to avoid incorrect disconnections.

---

### Proof of Concept

1. Peras is active; the ChainDB holds a non-empty `PerasWeightSnapshot` with boosts for blocks on the canonical chain.
2. A peer sends a header `H` at slot `s` that is beyond the local forecast horizon.
3. The ChainSync client enters the retry loop and calls `checkPreferTheirsOverOurs`.
4. `preferAnchoredCandidate (configBlock cfg) emptyPerasWeightSnapshot ourFrag theirFrag` is evaluated.
5. Because `isEmptyPerasWeightSnapshot emptyPerasWeightSnapshot = True`, the comparison uses only block count. The peer's chain has the same or fewer blocks than ours (but more Peras weight), so `shouldSwitch` returns `False`.
6. The node throws `CandidateTooSparse` and disconnects from the peer.
7. The actual `chainSelection` in `ChainSel.hs` — which uses the real `weights` from `ChainSelEnv` — would have preferred the peer's chain, but the peer is now gone.
8. The node stays on the non-canonical chain.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs (L298-311)
```haskell
                , GSM.getCandidateOverSelection = do
                    weights <- ChainDB.getPerasWeightSnapshot chainDB
                    pure $ \(headers, _lst) state ->
                      case AF.intersectionPoint headers (csCandidate state) of
                        Nothing -> GSM.CandidateDoesNotIntersect
                        Just{} ->
                          GSM.WhetherCandidateIsBetter $ -- precondition requires intersection
                            shouldSwitch
                              ( preferAnchoredCandidate
                                  (configBlock cfg)
                                  (forgetFingerprint weights)
                                  headers
                                  (csCandidate state)
                              )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1050-1050)
```haskell
  , weights :: PerasWeightSnapshot blk
```
