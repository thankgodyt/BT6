### Title
Chain-selection inconsistency: `checkPreferTheirsOverOurs` uses `emptyPerasWeightSnapshot` while `chainSelectionForBlock` uses the live Peras weight snapshot - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The ChainSync client's `checkPreferTheirsOverOurs` guard evaluates chain preference with `emptyPerasWeightSnapshot` (ignoring all Peras certificate weights), while the actual chain-selection loop in `chainSelectionForBlock` evaluates the identical preference question with the real, live `PerasWeightSnapshot`. This is a direct analog of the external report's root cause: the same logical decision is made with different state in two different code paths. When Peras certificates are present, the two paths can reach opposite conclusions for the same pair of chains, causing an honest node to disconnect from a peer whose chain is genuinely canonical under Peras, and to remain permanently on a less-secure chain.

---

### Finding Description

**Path 1 — ChainSync client disconnect guard** (`checkPreferTheirsOverOurs`):

When a received header is beyond the local forecast horizon, the ChainSync client blocks in `readLedgerStateHelper` waiting for the local chain to advance. Before each `retry` it calls `checkPreferTheirsOverOurs` to decide whether to stay connected or disconnect. The preference check is:

```haskell
shouldSwitch $
  preferAnchoredCandidate
    (configBlock cfg)
    -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
    emptyPerasWeightSnapshot   -- ← always empty; ignores all Peras certs
    ourFrag
    theirFrag
```

If the result is not `ShouldSwitch`, the client throws `CandidateTooSparse` and disconnects. [1](#0-0) 

The call site in `readLedgerStateHelper` that triggers this guard: [2](#0-1) 

**Path 2 — Actual chain selection** (`chainSelectionForBlock`):

The real chain-selection loop atomically fetches the live Peras weight snapshot and passes it to the same `preferAnchoredCandidate` function:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [3](#0-2) 

The preference check using real weights:

```haskell
ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
``` [4](#0-3) 

**The inconsistency**: Both paths call `preferAnchoredCandidate` to answer "should we prefer the candidate chain over ours?" but supply different `PerasWeightSnapshot` values. Path 1 always supplies an empty snapshot; Path 2 supplies the real snapshot. When Peras certificates are present, the two paths can reach opposite conclusions for the same pair of chains — exactly the state-ordering inconsistency described in the external report.

---

### Impact Explanation

Under Peras, a candidate chain that is shorter by block count but carries sufficient Peras certificate weight is the canonical, more-secure chain. When such a candidate's tip header falls beyond the forecast horizon:

1. `checkPreferTheirsOverOurs` evaluates the candidate as *not* preferable (empty weights → pure block-count comparison → shorter chain loses).
2. The client throws `CandidateTooSparse` and disconnects from the peer.
3. `chainSelectionForBlock` would have evaluated the same candidate as *preferable* (real weights → Peras-weighted comparison → shorter chain with certificates wins).
4. The node never downloads the block bodies, never runs chain selection for this candidate, and remains on the less-secure chain.

If all peers serving the canonical Peras-weighted chain are disconnected this way, the node is permanently stuck on a non-canonical chain — a consensus safety failure matching the **High** impact tier: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

---

### Likelihood Explanation

The trigger is reachable by any peer without special privileges: serve a header whose slot is beyond the local forecast horizon. No keys, stake, or operator access are required. The inconsistency only has observable effect once Peras certificates are live on the network and a candidate chain's preference is determined by certificate weight rather than block count alone. Peras is actively being integrated — the TODO comment in `checkPreferTheirsOverOurs` itself references an open tracking issue — making this a near-term production risk rather than a purely theoretical one.

---

### Recommendation

Pass the real `PerasWeightSnapshot` to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, consistent with how `chainSelectionForBlock` does it. Alternatively, remove the `checkPreferTheirsOverOurs` guard entirely as the TODO comment already proposes, since the guard's purpose — avoiding indefinite blocking on chains the node would never adopt — is already served by the Limit-on-Patience (LoP) bucket mechanism.

---

### Proof of Concept

1. Node A holds `ourFrag` of length *k* with no Peras certificates; the live `weights` snapshot contains a certificate boosting a competing chain.
2. Peer B serves `theirFrag` of length *k−1* whose Peras certificate weight makes `preferAnchoredCandidate cfg weights ourFrag theirFrag = ShouldSwitch`.
3. Peer B sends a header at slot *S* that is beyond Node A's forecast horizon.
4. Node A enters `readLedgerStateHelper`; `projectLedgerView S lst` returns `Nothing` (outside forecast range).
5. `checkPreferTheirsOverOurs` is called; it evaluates `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag = StayWithCurrent` (block-count comparison only, shorter chain loses).
6. Node A throws `CandidateTooSparse` and disconnects from Peer B.
7. Node A never downloads Peer B's blocks; `chainSelectionForBlock` is never invoked for this candidate.
8. Node A remains on its length-*k* chain, which is non-canonical under Peras, while the correct Peras-weighted chain goes unadopted.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1819)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L776-778)
```haskell
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```
