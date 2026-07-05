### Title
Chain Selection Preference Check Uses Empty Peras Weights While Actual Selection Uses Real Weights — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

In the ChainSync client, when a peer's header is beyond the forecast horizon, the node calls `checkPreferTheirsOverOurs` to decide whether to disconnect. This check evaluates chain preference using `emptyPerasWeightSnapshot` (no Peras certificate boosts). However, the actual chain selection in `ChainSel.hs` evaluates preference using the real `PerasWeightSnapshot` (which includes Peras certificate boosts). This is the direct analog of the external report's pattern: a validation/guard check is performed on value A (empty weights), but the actual operation uses value B (real weights).

---

### Finding Description

In `ChainSync/Client.hs`, `checkPreferTheirsOverOurs` is invoked when a header is beyond the forecast horizon. If the peer's fragment is not preferred over ours, the node disconnects. The preference check is:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← guard uses EMPTY weights
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

The actual chain selection in `chainSelectionForBlock` reads the real Peras weight snapshot and passes it through to `preferAnchoredCandidate`:

```haskell
(invalid, curChain, weights) <- atomically $
  (,,)
    <$> ...
    <*> Query.getCurrentChain cdb
    <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)  -- ← real weights
``` [2](#0-1) 

And the `chainSelection` function asserts all candidates are preferred using those real weights:

```haskell
assert
  ( all
      (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
      chainDiffs
  )
``` [3](#0-2) 

The mismatch is structural: the guard that decides whether to keep the peer connection uses `emptyPerasWeightSnapshot`, while the downstream selection that would actually adopt the chain uses the real snapshot. The TODO comment at line 1841–1842 explicitly acknowledges this is a known defect referencing `cardano-peras/issues/64`. [4](#0-3) 

---

### Impact Explanation

When a peer's chain contains a Peras-boosted block (a block whose weight is elevated by a valid Peras certificate), the following scenario arises:

1. The peer sends headers that extend beyond the local forecast horizon.
2. `checkPreferTheirsOverOurs` evaluates the candidate using `emptyPerasWeightSnapshot` — Peras boosts are invisible.
3. Without the boost, the peer's chain appears equal-length or shorter than the local chain, so `shouldSwitch` returns `False`.
4. The node throws `CandidateTooSparse` and disconnects from the peer.
5. The actual chain selection — which would have used real weights and found the peer's chain preferred — is never reached.
6. The honest node permanently fails to adopt the better Peras-boosted chain, preferring a non-canonical, less-secure chain.

This matches the **High** allowed impact: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Currently low, but structurally certain once Peras is activated.** At present, `getPerasCertInBlock _ = Nothing` means no certificates are extracted from blocks, so `weights` is always empty in practice and the mismatch has no observable effect. [5](#0-4) 

However, the code path is in production files, the Peras weight infrastructure is fully wired into `chainSelectionForBlock` and `chainSelSync`, and the TODO comment confirms the developers are aware the check must be corrected before Peras is live. Once Peras certificates are extracted from blocks, any honest peer serving a Peras-boosted chain whose headers happen to be beyond the local forecast horizon will trigger the disconnect, with no adversarial action required.

---

### Recommendation

Pass the real `PerasWeightSnapshot` into `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`. The snapshot is already available in the `ChainDbView` or can be threaded through `ConfigEnv`/`DynamicEnv`. This ensures the guard and the actual selection use the same preference criterion, eliminating the mismatch.

---

### Proof of Concept

1. Node A has a local chain of length N with no Peras certificates.
2. Peer B has a chain of length N whose tip block carries a Peras certificate boost (weight > 0), making it preferred under real weights.
3. Peer B's chain tip is beyond Node A's forecast horizon (e.g., a large slot gap).
4. Node A calls `checkPreferTheirsOverOurs` with `emptyPerasWeightSnapshot`.
5. Without the boost, both chains appear equal-length; `preferAnchoredCandidate` returns `PreferCurrent`; `shouldSwitch` is `False`.
6. Node A throws `CandidateTooSparse` and disconnects from Peer B.
7. Node A never runs `chainSelectionForBlock` with real weights, never adopts the Peras-boosted chain, and remains on the non-canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1128-1132)
```haskell
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```
