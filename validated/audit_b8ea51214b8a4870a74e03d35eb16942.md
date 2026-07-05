### Title
ChainSync Forecast-Horizon Disconnect Guard Uses Hardcoded Empty Peras Weight Snapshot, Causing Chain Selection Failure When Peras Is Active — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client is the gate that decides whether to disconnect from a peer while waiting for the forecast horizon to advance. It unconditionally passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate`, ignoring any Peras certificate weight. The actual chain-selection logic in `ChainSel.hs` reads the live `PerasWeightSnapshot` from ChainDB. This inconsistency means that once Peras is active, a peer serving a valid chain that is heavier only due to Peras certificate boosts (not raw block count) will be incorrectly disconnected with `CandidateTooSparse`, and the honest node will permanently fail to adopt the canonically heavier chain.

---

### Finding Description

**Root cause — the gate uses a hardcoded empty snapshot**

`checkPreferTheirsOverOurs` is called inside `readLedgerStateHelper` every time `projectLedgerView` returns `Nothing` (i.e., the incoming header is beyond the current forecast horizon). Its purpose is to disconnect from peers whose candidate chain is not worth waiting for. The decision is made by calling `preferAnchoredCandidate`:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, never the live snapshot
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

**Contrast — actual chain selection reads the live snapshot**

`chainSelectionForBlock` in `ChainSel.hs` atomically reads the real `PerasWeightSnapshot` from ChainDB before every chain-selection decision:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [2](#0-1) 

The same live snapshot is used in `BlockFetchClientInterface` and `NodeKernel` for GSM candidate comparison. [3](#0-2) 

**How `preferAnchoredCandidate` behaves with empty vs. live weights**

When `isEmptyPerasWeightSnapshot weights` is `True`, `preferAnchoredCandidate` falls into the block-count-only branch and returns `ShouldNotSwitch` whenever the candidate tip's `BlockNo` is ≤ ours. When the live snapshot is non-empty (Peras active), it computes `wsvTotalWeight = BlockNo + PerasWeightBoost` and can return `ShouldSwitch` even for a candidate with equal or fewer raw blocks if its Peras boost is large enough. [4](#0-3) [5](#0-4) 

**End-to-end exploit path**

1. Peras is active; the ChainDB `PerasWeightSnapshot` contains certificate boosts for blocks on the honest chain.
2. An honest peer's candidate chain has the same or fewer raw blocks as the local chain but a larger total weight (`BlockNo + PerasBoost`).
3. The peer sends a header whose slot is beyond the current forecast horizon; `projectLedgerView` returns `Nothing`.
4. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs` with `emptyPerasWeightSnapshot`.
5. `preferAnchoredCandidate` sees equal/fewer blocks and no Peras weight → `ShouldNotSwitch`.
6. `throwSTM CandidateTooSparse` fires; the ChainSync client disconnects from the peer.
7. The node never downloads or validates the heavier chain; it remains on the lighter, less-secure chain.

The attacker-controlled entry path is a crafted (or honest) peer message: a `RollForward` header for a slot beyond the forecast horizon on a Peras-boosted chain. No keys, no admin access, no stake majority required.

---

### Impact Explanation

The node permanently prefers a non-canonical chain over the canonically heavier Peras-boosted chain. This is a **chain selection failure**: the node's selection diverges from the honest majority's selection in a way that cannot be corrected by normal protocol operation (the peer is disconnected and the heavier chain is never fetched). This falls squarely within:

> *High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

The bug is latent in production code today. It is triggered the moment Peras certificates are live on the network and a peer's chain is heavier by Peras weight alone while also containing a slot gap exceeding the forecast window. The developers have already flagged the check as incorrect (the `TODO` at line 1841 references `cardano-peras/issues/64`). Likelihood is **medium**: requires Peras activation, but once active, any honest peer serving a Peras-boosted chain with a large slot gap triggers it without any special capability.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` obtained from ChainDB (the same snapshot used by `chainSelectionForBlock`). The ChainSync client already has access to `chainDbView`; `getPerasWeightSnapshot` should be threaded through `ConfigEnv` or `DynamicEnv` and read atomically alongside `intersectsWithCurrentChain` inside `readLedgerStateHelper`. This ensures the disconnect guard and the actual chain-selection logic use the same weight metric, eliminating the inconsistency.

---

### Proof of Concept

```
Setup (Peras active, k=2160):
  ourChain:   ... → B_99  (BlockNo 99, PerasBoost 0,  total weight 99)
  theirChain: ... → B_99 → B_100 (BlockNo 100, PerasBoost 500, total weight 600)
  Slot of B_100 > forecastHorizon(ourChain)

Step 1: Peer sends RollForward(header(B_100))
Step 2: projectLedgerView(slot(B_100)) → Nothing  (beyond forecast horizon)
Step 3: readLedgerStateHelper calls checkPreferTheirsOverOurs
Step 4: preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag
        → compares BlockNo 99 vs BlockNo 100 → ShouldSwitch  ← OK in this example

Adjusted scenario (equal block count, Peras-only advantage):
  ourChain:   ... → B_100 (BlockNo 100, PerasBoost 0,   total weight 100)
  theirChain: ... → B_100'(BlockNo 100, PerasBoost 500, total weight 600)
  Slot of B_100' > forecastHorizon

Step 4: preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag
        → compares BlockNo 100 vs BlockNo 100 → falls to tiebreaker → ShouldNotSwitch
Step 5: throwSTM CandidateTooSparse  ← peer disconnected
Step 6: Real chainSelectionForBlock would have used total weight 100 vs 600 → ShouldSwitch
        but the block is never fetched.
```

The node is now stuck on a chain with total weight 100 while the honest majority is on weight 600.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs (L299-311)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
