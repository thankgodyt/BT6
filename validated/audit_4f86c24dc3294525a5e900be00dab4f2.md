### Title
ChainSync Client Uses Stale Empty Peras Weight Snapshot in `checkPreferTheirsOverOurs`, Causing Incorrect Disconnection from Peers Serving the Canonical Peras-Boosted Chain - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When a candidate header is beyond the forecast horizon, the ChainSync client evaluates whether the candidate chain is still preferable to the node's current chain using a hardcoded `emptyPerasWeightSnapshot` (zero Peras weights) instead of the live `PerasWeightSnapshot` from the ChainDB. Under Peras, a candidate chain with fewer blocks but sufficient Peras certificate boosts can be the canonical chain. Because the weight comparison ignores those boosts, the node incorrectly concludes the candidate is not preferable and disconnects from the peer — staying on a lighter, non-canonical chain.

---

### Finding Description

The function `checkPreferTheirsOverOurs` is invoked from `readLedgerStateHelper` whenever `projectLedgerView` returns `Nothing` (i.e., the incoming header's slot is beyond the forecast horizon). Its purpose is to guard against waiting indefinitely for a candidate that will never be adopted: if the candidate is already not preferable to the current chain, the node disconnects immediately. [1](#0-0) 

The critical defect is on lines 1841–1842:

```haskell
preferAnchoredCandidate
  (configBlock cfg)
  -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
  emptyPerasWeightSnapshot   -- ← always zero; ignores live Peras boosts
  ourFrag
  theirFrag
```

`preferAnchoredCandidate` dispatches on whether the weight snapshot is empty: [2](#0-1) 

When the snapshot is empty (as hardcoded here), the comparison falls back to pure block-count (`SelectView`/`BlockNo`) ordering. When the snapshot is non-empty (the live Peras case), it computes `weightedSelectView` over the suffix from the intersection, summing `BlockNo + PerasWeight` boosts.

Under Peras, a chain with fewer blocks but a large enough certificate boost has a higher total weight and is the canonical chain. The hardcoded empty snapshot makes the comparison blind to those boosts, so a Peras-boosted canonical candidate with fewer raw blocks than the node's current chain will fail the `shouldSwitch` test and trigger:

```haskell
throwSTM $ CandidateTooSparse mostRecentIntersection ...
``` [3](#0-2) 

The live snapshot is available via `ChainDB.getPerasWeightSnapshot` (an STM action) and is already used correctly in the GSM and in ChainSel: [4](#0-3) [5](#0-4) 

The `checkPreferTheirsOverOurs` call site is inside `readLedgerStateHelper`, which already runs in STM and already reads other STM state (via `intersectsWithCurrentChain` and `getPastLedger`), so reading the live snapshot there is straightforward. [6](#0-5) 

The `PerasWeightSnapshot` is exposed as an STM action on the ChainDB API: [7](#0-6) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer cause an honest node to prefer a non-canonical chain.**

Under Peras, `wsvTotalWeight = BlockNo + PerasWeight`. A chain with, say, `BlockNo = 99` and `PerasWeight = 5` (total 104) beats a chain with `BlockNo = 100` and `PerasWeight = 0` (total 100). The node's current chain may be the longer-by-block-count but lighter-by-total-weight chain. When a peer serves the heavier canonical chain and its tip is beyond the forecast horizon, `checkPreferTheirsOverOurs` evaluates the candidate as block-count-inferior and disconnects. The node remains on the non-canonical, lighter chain. If this affects enough nodes, it fragments the network's view of the canonical chain, undermining Peras's finality guarantees. [8](#0-7) 

---

### Likelihood Explanation

Requires Peras to be active (planned for Cardano mainnet). Once active, the scenario is realistic during initial sync or after a network partition: a peer serves a chain whose tip is more than one forecast window (≈3k/f slots, ~36 hours on mainnet) ahead of the node's intersection, and that chain carries enough certificate boosts to be heavier despite having fewer raw blocks. Any honest peer serving the canonical Peras chain can trigger this path — no adversarial behavior is required.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read from the ChainDB. Since `readLedgerStateHelper` already executes in STM and the `ChainDbView` record already carries `getPerasWeightSnapshot`: [9](#0-8) 

the fix is to thread `getPerasWeightSnapshot` into the `checkPreferTheirsOverOurs` closure (or read it inline in the STM block) and pass `forgetFingerprint weights` to `preferAnchoredCandidate`, mirroring the pattern already used in the GSM and ChainSel. The TODO comment at line 1841 (`-- TODO: remove this entire check`) indicates the developers intend to remove the check entirely once the Peras integration is complete; until then, the snapshot must not be hardcoded to empty.

---

### Proof of Concept

**Setup (Peras active, mainnet parameters):**

1. Node N has current chain `C_ours` with tip at `BlockNo = 100`, `PerasWeight = 0`, total weight = 100.
2. Peer P serves chain `C_cand` with tip at `BlockNo = 99`, `PerasWeight = 5` (one Peras certificate boosting a block on `C_cand`), total weight = 104. `C_cand` is the canonical chain.
3. The tip of `C_cand` is beyond N's forecast horizon (its slot is > `forecastAt + stabilityWindow`).

**Execution path:**

- `rollForward` receives the tip header of `C_cand`.
- `checkTime` → `readLedgerState` → `readLedgerStateHelper`: `projectLedgerView` returns `Nothing` (beyond forecast horizon).
- `checkPreferTheirsOverOurs` is called with `emptyPerasWeightSnapshot`.
- `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag` compares `BlockNo 100` vs `BlockNo 99` → `ShouldNotSwitch GT`.
- `shouldSwitch` returns `False` → `throwSTM (CandidateTooSparse ...)`.
- N disconnects from P.

**Result:** N stays on `C_ours` (total weight 100) and rejects `C_cand` (total weight 104, the canonical chain). The correct behavior — using the live snapshot — would yield `ShouldSwitch` and keep the connection open until the forecast horizon advances. [1](#0-0) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1794-1819)
```haskell
  readLedgerStateHelper kis prj = atomically $ do
    -- We must first find the most recent intersection with the current
    -- chain. Note that this is cheap when the chain and candidate haven't
    -- changed.
    intersectsWithCurrentChain kis >>= \case
      NoLongerIntersects -> return exitEarly
      StillIntersects () kis' -> do
        let KnownIntersectionState
              { mostRecentIntersection
              } = kis'
        lst <-
          fmap
            ( maybe
                ( error $
                    "intersection not within last k blocks: "
                      <> show mostRecentIntersection
                )
                ledgerState
            )
            $ getPastLedger mostRecentIntersection
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1132)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L64-84)
```haskell
data ChainDbView m blk = ChainDbView
  { getCurrentChain :: STM m (AnchoredFragment (Header blk))
  , getCurrentChainWithTime :: STM m (AnchoredFragment (HeaderWithTime blk))
  , getIsFetched :: STM m (Point blk -> Bool)
  , getMaxSlotNo :: STM m MaxSlotNo
  , addBlockAsync :: InvalidBlockPunishment m -> blk -> m (AddBlockPromise m blk)
  , getChainSelStarvation :: STM m ChainSelStarvation
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  }

defaultChainDbView :: ChainDB m blk -> ChainDbView m blk
defaultChainDbView chainDB =
  ChainDbView
    { getCurrentChain = ChainDB.getCurrentChain chainDB
    , getCurrentChainWithTime = ChainDB.getCurrentChainWithTime chainDB
    , getIsFetched = ChainDB.getIsFetched chainDB
    , getMaxSlotNo = ChainDB.getMaxSlotNo chainDB
    , addBlockAsync = ChainDB.addBlockAsync chainDB
    , getChainSelStarvation = ChainDB.getChainSelStarvation chainDB
    , getPerasWeightSnapshot = ChainDB.getPerasWeightSnapshot chainDB
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L44-57)
```haskell
-- | Data structure for tracking the weight of blocks due to Peras boosts.
newtype PerasWeightSnapshot blk = PerasWeightSnapshot
  { getPerasWeightSnapshot :: Map (Point blk) PerasWeight
  }
  deriving stock Eq
  deriving Generic
  deriving newtype NoThunks

instance StandardHash blk => Show (PerasWeightSnapshot blk) where
  show = show . perasWeightSnapshotToList

-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
