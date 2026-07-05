### Title
Stale `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` Causes Incorrect Peer Disconnection Under Peras — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When Peras is enabled, the ChainSync client's `checkPreferTheirsOverOurs` guard uses a hardcoded `emptyPerasWeightSnapshot` — zero Peras certificate boosts — instead of the live `PerasWeightSnapshot` when deciding whether to disconnect from a peer whose header is beyond the forecast horizon. This is the direct analog of the external report's stale-exchange-rate bug: a cached/outdated value is used for a critical decision that should use the current value, causing the node to make the wrong chain-selection choice.

---

### Finding Description

When the ChainSync client receives a header whose slot is beyond the current forecast horizon, it cannot yet obtain a `LedgerView` to validate it. Rather than blocking indefinitely, it calls `checkPreferTheirsOverOurs` to decide whether the peer's candidate chain is worth waiting for. If the candidate is not preferred over the node's own chain, the client disconnects immediately. [1](#0-0) 

The comparison is performed by `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot` to account for Peras certificate boosts. The call site hard-codes `emptyPerasWeightSnapshot`:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always zero boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [2](#0-1) 

The live `PerasWeightSnapshot` is available from the ChainDB via `getPerasWeightSnapshot`: [3](#0-2) 

and is correctly used everywhere else in chain selection: [4](#0-3) 

`preferAnchoredCandidate` itself branches on whether the snapshot is empty, so passing `emptyPerasWeightSnapshot` silently disables the Peras-weighted comparison and falls back to pure block-count comparison: [5](#0-4) 

**Stale-state analogy to the external report:**

| External report (Derby Vault) | This finding (Ouroboros Consensus) |
|---|---|
| `exchangeRate` cached from last rebalance | `emptyPerasWeightSnapshot` hard-coded at zero |
| Attacker deposits at stale rate, withdraws at updated rate | Node evaluates candidate chain with stale (zero) weights, disconnects from the heavier canonical chain |
| Gap between stale and current state is exploitable | Gap between empty weights and actual Peras boosts causes wrong `ShouldSwitch` decision |

---

### Impact Explanation

When Peras is enabled and a Peras certificate has boosted a block on a candidate chain, that chain may be **heavier** (higher `wsvTotalWeight`) than the node's current chain even though it is **shorter** in raw block count. With `emptyPerasWeightSnapshot`, `checkPreferTheirsOverOurs` evaluates the candidate using only block count, concludes `ShouldNotSwitch`, and disconnects from the peer. The node then remains on its current, lighter chain.

This is a **High** chain-selection bug: an honest node is made to prefer a non-canonical, less-secure chain over the canonical Peras-weighted chain, triggered by a normal unprivileged peer serving valid headers beyond the forecast horizon. The impact matches: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The bug is latent when Peras is disabled (the current mainnet default) because `emptyPerasWeightSnapshot` is then correct. It becomes active as soon as Peras is enabled on any network (private testnet, pre-production, or future mainnet). On a Peras-enabled network, the scenario — a peer's header beyond the forecast horizon while that peer's chain carries a certificate boost — is a normal operating condition, not an edge case. No special privileges, key material, or stake majority are required; any peer serving valid Peras-boosted headers triggers the path.

---

### Recommendation

Replace the hard-coded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read atomically from the ChainDB (already available in the `ConfigEnv` or `DynamicEnv` passed to the ChainSync client). The existing TODO comment at line 1841 already tracks this under https://github.com/tweag/cardano-peras/issues/64; the fix should be prioritised before Peras is enabled on any network. [6](#0-5) 

---

### Proof of Concept

1. Start a private testnet with Peras enabled.
2. Arrange two peers for an honest node:
   - **Peer A** holds the node's current chain of length *N* (no Peras boosts).
   - **Peer B** holds a chain of length *N − 1* whose tip block is boosted by a valid Peras certificate, making its `wsvTotalWeight` exceed that of Peer A's chain.
3. Ensure Peer B's next header slot is beyond the node's current forecast horizon (achievable by a slot gap larger than `stabilityWindow`).
4. Observe: `checkPreferTheirsOverOurs` evaluates Peer B's chain with `emptyPerasWeightSnapshot` → block count *N − 1 < N* → `ShouldNotSwitch` → node throws `CandidateTooSparse` and disconnects from Peer B.
5. The node remains on Peer A's lighter chain, never adopting the canonical Peras-heavier chain from Peer B.

The root cause is at: [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L631-635)
```haskell
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

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
