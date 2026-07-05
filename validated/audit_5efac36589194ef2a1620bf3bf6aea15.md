### Title
Stale (Always-Empty) Peras Weight Snapshot in `checkPreferTheirsOverOurs` Causes Incorrect Chain-Selection Disconnect — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client hardcodes `emptyPerasWeightSnapshot` instead of reading the live Peras weight snapshot from the ChainDB. When Peras is active and blocks have been boosted by Peras certificates, this permanently-stale (always-empty) snapshot causes the node to evaluate chain preference without Peras boosts, potentially disconnecting from a peer that is offering the canonical Peras-preferred chain.

---

### Finding Description

`checkPreferTheirsOverOurs` is invoked from `readLedgerStateHelper` whenever a peer's header is beyond the forecast horizon and the node cannot yet validate it. Its purpose is to decide whether the peer's candidate chain is at least as good as the node's current selection; if not, the node disconnects with `CandidateTooSparse`. [1](#0-0) 

The comparison is performed by `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot blk` argument that encodes the Peras-certificate-derived weight boosts for blocks on the chain. In `checkPreferTheirsOverOurs`, this argument is unconditionally supplied as `emptyPerasWeightSnapshot` — a constant empty map with no boosts: [2](#0-1) 

The developer comment on that line reads:
> `-- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64`

This acknowledges the problem but leaves the stale snapshot in place.

By contrast, the BlockFetch client interface reads the **live** snapshot from the ChainDB for every chain comparison it performs: [3](#0-2) 

`preferAnchoredCandidate` itself is correct: when the snapshot is non-empty it computes the full weighted comparison; when it is empty it falls back to the standard Praos length/`selectView` comparison: [4](#0-3) 

The root cause is therefore that `checkPreferTheirsOverOurs` never reads the updated snapshot from the ChainDB. The snapshot it uses is permanently stale (always empty), even after the ChainDB has recorded Peras certificate boosts for blocks on the candidate chain.

`emptyPerasWeightSnapshot` is defined as: [5](#0-4) 

---

### Impact Explanation

**High — Chain selection error.**

When Peras is active and a peer's candidate chain contains Peras-boosted blocks, the weighted total of that chain may exceed the node's current selection even though the raw Praos length is equal or shorter. `checkPreferTheirsOverOurs` evaluates the comparison with empty weights, so it sees the candidate as no better than the current chain and throws `CandidateTooSparse`, disconnecting from the peer. The node is then unable to adopt the canonical Peras-preferred chain from that peer. A different peer offering the same canonical chain would trigger the same disconnect for the same reason. The node can become permanently stuck on a non-canonical chain without any operator fault.

This matches the allowed impact class: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Low-to-Medium.** Peras is not yet deployed on Cardano mainnet, so the bug is currently dormant. However, the code is in production files, Peras development is active, and the condition that triggers the bug (a peer's header beyond the forecast horizon while Peras boosts exist on the candidate chain) is a normal operating scenario once Peras is live. No special privileges, keys, or stake are required; any peer that sends headers beyond the forecast horizon while the ChainDB holds non-empty Peras weights will trigger the path.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read from the ChainDB, mirroring the pattern already used in `BlockFetchClientInterface`:

```haskell
-- current (stale):
preferAnchoredCandidate
  (configBlock cfg)
  emptyPerasWeightSnapshot   -- always empty, ignores Peras boosts
  ourFrag
  theirFrag

-- corrected:
weights <- getPerasWeightSnapshot  -- read live snapshot from ChainDB
preferAnchoredCandidate
  (configBlock cfg)
  weights
  ourFrag
  theirFrag
```

If the intent of the TODO is to remove `checkPreferTheirsOverOurs` entirely (per issue #64), that removal should be expedited before Peras is deployed, as the current code is unsafe under Peras.

---

### Proof of Concept

1. Peras is active; the ChainDB holds a non-empty `PerasWeightSnapshot` with boosts for blocks on the canonical chain.
2. A peer sends a sequence of headers. The last header's slot is beyond the forecast horizon of the node's current intersection ledger state.
3. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs`.
4. `checkPreferTheirsOverOurs` calls `preferAnchoredCandidate (configBlock cfg) emptyPerasWeightSnapshot ourFrag theirFrag`.
5. Because `isEmptyPerasWeightSnapshot emptyPerasWeightSnapshot` is `True`, the function falls back to the raw Praos `selectView` comparison.
6. The peer's chain has the same raw Praos length as ours (or is shorter), so `preferAnchoredCandidate` returns `ShouldNotSwitch`.
7. `checkPreferTheirsOverOurs` throws `CandidateTooSparse`, disconnecting from the peer.
8. The actual weighted comparison (using the live snapshot) would have returned `ShouldSwitch`, because the Peras boosts make the peer's chain heavier.
9. The node is now disconnected from the peer offering the canonical Peras-preferred chain and remains on the non-canonical chain. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1851)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-241)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
          }
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
