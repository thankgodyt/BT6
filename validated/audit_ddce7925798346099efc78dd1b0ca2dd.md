### Title
Chain Selection Bypass via Ignored Peras Weight Snapshot in `checkPreferTheirsOverOurs` — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

### Summary
The `checkPreferTheirsOverOurs` function in the ChainSync client hardcodes `emptyPerasWeightSnapshot` instead of using the actual live Peras weight snapshot when deciding whether to disconnect from a peer whose header is beyond the forecast horizon. When Peras is enabled, this causes the node to incorrectly judge a heavier (Peras-boosted) candidate chain as non-preferred and disconnect from the peer, permanently preventing adoption of the canonically heavier chain. The pattern is a direct analog to the external report: a guard that should use the correct data uses a zeroed-out substitute, causing the downstream decision to be wrong.

### Finding Description

**Root cause — wrong data passed to the preference check.**

`checkPreferTheirsOverOurs` is called inside `readLedgerStateHelper` whenever `projectLedgerView` returns `Nothing` (the incoming header is beyond the forecast horizon). Its job is to decide whether the node should keep waiting for its own chain to advance (so the header can eventually be validated) or disconnect immediately because the peer's chain will never be preferred anyway.

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs
-- lines 1814-1817
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
```

The function itself:

```haskell
-- lines 1834-1857
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot          -- ← always zero; ignores all Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
```

`preferAnchoredCandidate` has two code paths: when the weight snapshot is empty it falls back to a pure block-number comparison; when it is non-empty it computes the weighted suffix comparison that Peras requires.

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs
-- lines 186-213
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- tip-only block-number comparison, Peras boosts invisible
      ...
  | otherwise =
      -- weighted suffix comparison using actual boosts
      ...
```

Because `emptyPerasWeightSnapshot` is always passed, the Peras-aware branch is never reached inside `checkPreferTheirsOverOurs`. The actual live snapshot is available in the `ChainDB` API (`getPerasWeightSnapshot`) and is correctly used everywhere else in the chain-selection pipeline (e.g., `NodeKernel.hs` line 299-311, `ChainSel.hs` `constructPreferableCandidates`).

**Exploit path.**

Consider a Peras-enabled network where:

1. The victim node is on chain **A** with block-number tip `N` and no Peras boosts (total weight = N).
2. An honest peer holds chain **B** with block-number tip `N` but one Peras certificate boosting a block on **B** (total weight = N + boost > N).
3. Chain **B** has a slot gap large enough that the next header is beyond the victim's forecast horizon.

When the victim processes the peer's header:
- `projectLedgerView` returns `Nothing` → `checkPreferTheirsOverOurs` is called.
- `preferAnchoredCandidate … emptyPerasWeightSnapshot ourFrag theirFrag` compares only block numbers: both tips are at `N` → `ShouldNotSwitch EQ`.
- The victim throws `CandidateTooSparse` and disconnects.
- Chain **B** (the canonical, heavier chain) is never adopted.

The victim permanently stays on the lighter chain **A**, violating the Peras chain-selection invariant. No privileged keys or stake majority are required to trigger this: any peer that legitimately holds a Peras-boosted chain with a slot gap can cause it.

**Analog to the external report.**

The external report's root cause is that a guard (`unCollateralized` check) that should limit a computation is placed after the computation, so the wrong data is used. Here the guard (`checkPreferTheirsOverOurs`) that should use the live weight snapshot uses a zeroed substitute (`emptyPerasWeightSnapshot`), so the preference decision is made on incomplete data. In both cases the check exists but operates on the wrong input, producing an incorrect outcome that propagates to a security-relevant state change.

### Impact Explanation

When Peras is enabled, a node will incorrectly disconnect from peers whose Peras-boosted chain has a header beyond the forecast horizon, even when that chain is the canonical (heaviest) chain. The node stays on a lighter chain, violating the Peras security model which requires adoption of the heaviest chain. This is a chain-selection bug that causes an honest node to prefer a non-canonical, less-secure chain beyond the intended security assumptions of the Peras protocol.

### Likelihood Explanation

The trigger conditions are normal network events: a Peras certificate boosting a block on a fork, combined with a slot gap that pushes the next header beyond the forecast horizon. Both conditions arise in ordinary Peras operation. No adversarial capability beyond relaying valid network objects is required. The bug is self-activating for any honest peer in the described configuration.

### Recommendation

Pass the live `PerasWeightSnapshot` (obtained via `ChainDB.getPerasWeightSnapshot` or threaded through `DynamicEnv`) to `preferAnchoredCandidate` inside `checkPreferTheirsOverOurs`, mirroring the pattern already used in `NodeKernel.hs` (lines 299-311) and `ChainSel.hs`. The existing TODO comment acknowledges the problem and references issue #64; the minimal fix is to replace `emptyPerasWeightSnapshot` with the actual snapshot before that broader refactor lands.

### Proof of Concept

```
Setup (Peras-enabled private testnet):
  - Node V  : chain A, tip block-number N, no Peras boosts, total weight N.
  - Peer P  : chain B, tip block-number N, one Peras certificate boosting
              block B_k on chain B, total weight N + perasBoost > N.
              Chain B has a slot gap > stability window after B_k.

Sequence:
  1. P sends headers up to B_k to V; V validates them normally.
  2. P sends the next header H (slot gap > forecast horizon).
  3. V calls projectLedgerView for H → Nothing (beyond forecast horizon).
  4. V calls checkPreferTheirsOverOurs(ourFrag=A, th