### Title
Asymmetric Peras Weight Evaluation in ChainSync Disconnection Check vs. ChainDB Chain Selection Allows Non-Canonical Chain Preference — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client evaluates whether to disconnect from a peer using `emptyPerasWeightSnapshot` — completely ignoring Peras weight boosts — while the actual chain selection in ChainDB uses the real `PerasWeightSnapshot` populated from `PerasCertDB`. This is a direct analog to the external report's asymmetric base-value bug: one operation (disconnection gating) uses a stripped-down accounting base, while the paired operation (chain selection) uses the full accounting base. The result is that a node can be made to disconnect from a peer offering the canonical, Peras-heavier chain and remain on a lighter, non-canonical chain.

---

### Finding Description

**Root cause — `checkPreferTheirsOverOurs`:** [1](#0-0) 

The function is invoked when a received header is beyond the forecast horizon. It calls `preferAnchoredCandidate` with a hardcoded `emptyPerasWeightSnapshot`:

```haskell
preferAnchoredCandidate
  (configBlock cfg)
  -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
  emptyPerasWeightSnapshot
  ourFrag
  theirFrag
```

If the candidate does not appear preferred under this zero-weight snapshot, the node throws `CandidateTooSparse` and disconnects.

**Paired operation — actual ChainDB chain selection:**

Chain selection reads the real `PerasWeightSnapshot` from `PerasCertDB`: [2](#0-1) 

And passes it to `preferAnchoredCandidate`: [3](#0-2) 

The `PerasWeightSnapshot` is built from all certificates in `PerasCertDB`: [4](#0-3) 

**The asymmetry:**

`preferAnchoredCandidate` with Peras enabled computes total weight as `blockNo + weightBoost` over the suffix from the intersection: [5](#0-4) 

With `emptyPerasWeightSnapshot`, `weightBoost` is always zero, so the comparison degenerates to pure block count. With the real snapshot, a chain with fewer blocks but significant Peras certificate boosts can be heavier. The two code paths therefore evaluate the same pair of chains against different bases — exactly the deposit/withdraw asymmetry from the external report.

---

### Impact Explanation

Consider a node whose current chain has `N` blocks and weight `N` (no boosts). An honest peer offers a chain with `N-1` blocks but Peras-boosted weight `N-1 + B > N`. When that peer's tip is beyond the forecast horizon, `checkPreferTheirsOverOurs` fires. Using `emptyPerasWeight

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L774-778)
```haskell
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
