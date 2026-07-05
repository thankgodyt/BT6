### Title
`checkPreferTheirsOverOurs` Ignores Peras Weight Boosts, Causing Incorrect Peer Disconnection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` guard in the ChainSync client unconditionally passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate`, stripping all Peras certificate weight boosts from the comparison. When Peras is active, a peer serving a shorter-by-block-count but heavier-by-Peras-weight candidate chain is incorrectly judged as "not preferred" and disconnected with `CandidateTooSparse`. The node then permanently refuses to validate that candidate's headers beyond the forecast horizon, causing it to miss the legitimately heavier chain.

---

### Finding Description

The analog to the NFT-bid scenario is: a node that already "holds" a longer-by-block-count current chain is prevented from switching to a Peras-boosted candidate chain, because the ownership/possession check (the `checkPreferTheirsOverOurs` guard) ignores the Peras weight that would make the candidate the correct choice.

In `ChainSync/Client.hs`, `readLedgerStateHelper` blocks waiting for the forecast horizon to advance. While blocked, it calls `checkPreferTheirsOverOurs` to decide whether to keep waiting or disconnect:

```haskell
-- Client.hs ~line 1814-1817
case prj lst of
  Nothing -> do
    checkPreferTheirsOverOurs kis'
    retry
```

`checkPreferTheirsOverOurs` is:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always ignores Peras weights
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
```

The `emptyPerasWeightSnapshot` hardcode means `preferAnchoredCandidate` falls into its block-number-only comparison path (`isEmptyPerasWeightSnapshot weights = True`), comparing only `SelectView` (block number + VRF tiebreaker). If the peer's fragment has the same or fewer blocks than ours but carries a Peras certificate boost that makes it heavier in total weight, the check returns `ShouldNotSwitch` and the peer is disconnected.

The actual chain selection in `ChainSel.hs` correctly uses the live `PerasWeightSnapshot` from `cdbPerasCertDB`. The ChainSync client's guard does not.

---

### Impact Explanation

**High — Chain selection bug that lets an honest node prefer a non-canonical chain.**

When Peras is active:

1. A peer serves a candidate chain `C_peer` that is shorter by block count than the node's current chain `C_local`, but `C_peer` carries a Peras certificate boost making its total weight greater.
2. `C_peer`'s tip is beyond the current forecast horizon, so `readLedgerStateHelper` blocks and calls `checkPreferTheirsOverOurs`.
3. Because `emptyPerasWeightSnapshot` is used, the check computes `preferAnchoredCandidate` using block-number-only comparison, finds `C_peer` is not preferred, and throws `CandidateTooSparse`, disconnecting the peer.
4. The node never downloads or validates `C_peer`'s blocks, and permanently stays on the lighter (by Peras weight) chain `C_local`.
5. This violates the Peras chain selection invariant: the node selects a chain that is not the heaviest available, diverging from the canonical chain as seen by peers that correctly account for Peras weights.

This is a chain-selection correctness failure: an honest node is made to prefer a non-canonical, less-secure chain by a crafted sequence of Peras certificates and block arrivals, without any operator fault.

---

### Likelihood Explanation

Likelihood is **medium-high** once Peras is enabled on a production network. The trigger condition — a candidate fragment that is shorter by block count but heavier by Peras weight, whose tip is beyond the forecast horizon — is a normal operating condition during Peras cooldown/recovery periods and during initial sync. An adversary who can influence certificate issuance (or simply an honest network where the node is slightly behind) can reliably trigger this path.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live Peras weight snapshot, consistent with how `constructPreferableCandidates` and `chainSelectionForBlock` use it. The TODO comment at line 1841 already acknowledges this is incorrect and references issue #64. The fix is to thread the current `PerasWeightSnapshot` (already available via `cdbPerasCertDB` / `getPerasWeightSnapshot`) into the ChainSync client's `checkPreferTheirsOverOurs` call.

---

### Proof of Concept

**Root cause location:** [1](#0-0) 

The hardcoded `emptyPerasWeightSnapshot` at line 1842 causes `preferAnchoredCandidate` to use the block-number-only path: [2](#0-1) 

When `isEmptyPerasWeightSnapshot weights` is `True`, only `selectView` (block number + VRF tiebreaker) is compared — Peras weight boosts are entirely ignored.

The correct comparison path (used by `ChainSel.hs`) accounts for Peras weights via `weightedSelectView`: [3](#0-2) 

The call site in `readLedgerStateHelper` that triggers the incorrect disconnect: [4](#0-3) 

**Scenario:**

1. Peras is active; a certificate boosts block `B` on a fork `C_peer` that is 1 block shorter than `C_local` but has total Peras weight > `C_local`.
2. `C_peer`'s tip slot is beyond the forecast horizon at the intersection point.
3. `readLedgerStateHelper` blocks, calls `checkPreferTheirsOverOurs`.
4. `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag` returns `ShouldNotSwitch GT` (our fragment is longer by block count).
5. `throwSTM CandidateTooSparse` fires; the peer is disconnected.
6. The node remains on `C_local`, which has less total Peras weight than `C_peer` — a chain selection failure.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1817)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-203)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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
