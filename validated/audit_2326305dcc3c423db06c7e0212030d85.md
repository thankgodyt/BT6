### Title
Chain Selection Ignores Peras Weight Boosts in `checkPreferTheirsOverOurs`, Causing Incorrect Peer Disconnection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client hardcodes `emptyPerasWeightSnapshot` instead of forwarding the actual Peras weight snapshot when calling `preferAnchoredCandidate`. This is the direct structural analog of the "missing `payable`" bug: just as Solidity functions that invoke 0x swaps requiring ETH fees must be `payable` to receive and forward that ETH, the chain-selection check here must supply the actual Peras weights to correctly evaluate chain preference. Using an empty snapshot causes the function to silently ignore all Peras certificate boosts, potentially causing an honest node to disconnect from peers offering the canonical Peras-boosted chain.

---

### Finding Description

In `Client.hs`, `checkPreferTheirsOverOurs` is invoked when a peer's header is beyond the forecast horizon. Its purpose is to decide whether to wait (if the peer's chain is preferred) or disconnect with `CandidateTooSparse` (if it is not). The call to `preferAnchoredCandidate` is made with a hardcoded `emptyPerasWeightSnapshot`:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty; actual weights never forwarded
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` branches on whether the snapshot is empty. When it is empty, it falls back to the non-Peras path (comparing only block numbers and VRF tiebreakers). When it is non-empty, it computes the `weightedSelectView` — the sum of Peras certificate boosts — for each fragment suffix and uses that as the primary ordering criterion:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- non-Peras path: block number + VRF tiebreaker only
      ...
  | otherwise =
      -- Peras path: weighted select view (certificate boosts)
      case AF.intersect ours cand of
        ...
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
``` [2](#0-1) 

`emptyPerasWeightSnapshot` is defined as a map with no entries, so `isEmptyPerasWeightSnapshot` always returns `True` for it:

```haskell
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
``` [3](#0-2) 

The consequence: whenever a peer's chain is beyond the forecast horizon and the canonical chain is Peras-boosted (i.e., it carries certificate weight that makes it preferred over the node's current chain even though it is not strictly longer), `checkPreferTheirsOverOurs` evaluates the comparison without those boosts. If the peer's chain is not longer than the node's current chain, the check concludes "not preferred" and throws `CandidateTooSparse`, disconnecting from the peer — even though the peer is offering the correct canonical chain.

The `ChainSync` client imports `emptyPerasWeightSnapshot` explicitly for this purpose: [4](#0-3) 

---

### Impact Explanation

This is a **High** chain-selection bug. When the Peras protocol is active and the canonical chain carries certificate boosts that make it preferred over the node's current chain (without being strictly longer), `checkPreferTheirsOverOurs` will incorrectly classify the peer's chain as "too sparse" and disconnect. If this happens for all peers offering the canonical chain simultaneously — a realistic scenario during a Peras-boosted epoch boundary — the node remains on a non-canonical chain indefinitely until it reconnects and the forecast horizon advances. This violates the intended Peras security assumption that certificate-boosted chains are always preferred in chain selection.

---

### Likelihood Explanation

The bug is latent today (Peras is not yet deployed on mainnet) but is present in production code. Once Peras is activated, any node syncing a chain where the canonical tip carries a Peras boost but is not strictly longer than the node's current chain will trigger this path whenever a peer's header is beyond the forecast horizon. The entry path is fully unprivileged: any peer can send headers beyond the forecast horizon, causing `checkPreferTheirsOverOurs` to be evaluated. No key compromise, admin access, or stake majority is required.

---

### Recommendation

Pass the actual `PerasWeightSnapshot` — sourced from the node's Peras state — into `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`. The snapshot is already threaded through `initialChainSelection` and the main ChainDB chain-selection path; the same mechanism should be used here. The existing TODO comment (`-- TODO: remove this entire check`) acknowledges the issue but does not fix it; until the check is removed, it must use the correct weights.

---

### Proof of Concept

1. Activate Peras on a private testnet.
2. Produce a chain where the canonical tip has a Peras certificate boost but is the same block number as the node's current tip (equal-length chains, Peras boost makes the canonical chain preferred).
3. Have a peer serve headers for this canonical chain where the tip is beyond the node's forecast horizon.
4. `checkPreferTheirsOverOurs` is invoked. It calls `preferAnchoredCandidate` with `emptyPerasWeightSnapshot`.
5. `isEmptyPerasWeightSnapshot` returns `True`; the non-Peras path is taken; the chains compare as equal (same block number, same VRF tiebreaker).
6. `shouldSwitch` returns `False`; `throwSTM CandidateTooSparse` fires; the node disconnects from the peer.
7. The node remains on the non-canonical chain. The canonical Peras-boosted chain is never adopted.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L128-128)
```haskell
import Ouroboros.Consensus.Peras.Weight (emptyPerasWeightSnapshot)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L56-57)
```haskell
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
