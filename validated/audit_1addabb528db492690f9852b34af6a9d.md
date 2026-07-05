### Title
Stale `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` Causes Incorrect Chain Selection at Forecast Horizon — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When Peras is active, the ChainSync client's `checkPreferTheirsOverOurs` guard uses a hardcoded `emptyPerasWeightSnapshot` instead of the live Peras weight snapshot when deciding whether to disconnect from a peer whose headers are beyond the forecast horizon. This creates a systematic inconsistency with the actual chain-selection logic in `ChainSel.hs`, which uses the real snapshot. A node can be made to disconnect from an honest peer offering the canonical (Peras-heavier) chain and remain on a non-canonical chain.

---

### Finding Description

When the ChainSync client receives a header whose slot is beyond the current forecast horizon, `projectLedgerView` returns `Nothing` and the client enters a retry loop inside `readLedgerStateHelper`. Before retrying it calls `checkPreferTheirsOverOurs` to decide whether to keep waiting or disconnect:

```haskell
-- Client.hs lines 1834–1857
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty, ignores Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [1](#0-0) 

The actual chain-selection path in `ChainSel.hs` uses the real `PerasWeightSnapshot` obtained from `getPerasWeightSnapshot` in the ChainDB API:

```haskell
-- ChainSel.hs line 177
[ (chain, reason)
| chain <- chains
, ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
]
``` [2](#0-1) 

`preferAnchoredCandidate` branches on whether the snapshot is empty. With a non-empty snapshot it computes `weightedSelectView` (block count + Peras boost) for both suffix fragments and compares total weight. With an empty snapshot it falls back to comparing raw `SelectView` (block count only): [3](#0-2) 

`WeightedSelectView` combines `wsvBlockNo` and `wsvWeightBoost` into `wsvTotalWeight`: [4](#0-3) 

The `PerasWeightSnapshot` is populated from validated Peras certificates stored in `PerasCertDB`: [5](#0-4) 

The ChainDB exposes the live snapshot via `getPerasWeightSnapshot`: [6](#0-5) 

---

### Impact Explanation

When Peras is active, a peer's chain fragment can be **heavier** than the local chain (due to certificate boosts on one or more blocks) while being **shorter** in raw block count. In that scenario:

- `checkPreferTheirsOverOurs` with `emptyPerasWeightSnapshot` sees the peer's fragment as shorter → `ShouldNotSwitch` → throws `CandidateTooSparse` → **disconnects**.
- The actual chain-selection logic with the real snapshot would see the peer's fragment as heavier → `ShouldSwitch` → would adopt it.

The node therefore disconnects from an honest peer offering the canonical chain and remains on a non-canonical (lighter) chain. If all peers offering the canonical chain have headers beyond the forecast horizon simultaneously (e.g., during a low-density period or after a burst of Peras certificates), the node can be stranded on the non-canonical chain indefinitely. This is a chain-selection safety failure: an honest node prefers a less-secure chain beyond the intended security assumptions of the Peras protocol.

This maps directly to the analog of the external report: the oracle price update creates a transition window where old state is used instead of new state. Here, the forecast horizon creates a transition window where the node must make a chain-selection decision, and it uses stale/empty weight state instead of the live Peras weight state.

---

### Likelihood Explanation

- **Peras must be active.** The CHANGELOG notes "if Peras is disabled (which is the default), there is no observable difference." The vulnerability is latent in production code and activates when Peras is enabled.
- **Entry path is unprivileged.** Any peer can send headers beyond the forecast horizon as a normal part of the ChainSync protocol; no special privileges are required.
- **Trigger condition is realistic.** A Peras certificate boosting a block on the canonical chain is a normal protocol event. A header beyond the forecast horizon occurs whenever the peer's chain is more than one stability window ahead of the intersection point, which happens during initial sync or after network partitions.
- **The developers have already identified this issue** (the `TODO` comment references https://github.com/tweag/cardano-peras/issues/64), confirming it is a known real defect, not a theoretical concern.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` read from the ChainDB (via `getPerasWeightSnapshot`). The snapshot is already available in the `ChainDbView` passed to the ChainSync client. The comparison must use the same weight source as the actual chain-selection logic in `ChainSel.hs` to maintain consistency. [7](#0-6) 

---

### Proof of Concept

**Setup (Peras active, `k = 2160`):**

1. Node's current chain `C_local`: 100 blocks, no Peras boosts → total weight = 100.
2. Peer's chain `C_peer`: 99 blocks, block at slot S has a Peras certificate boost of +5 → total weight = 104.
3. Peer sends header H at slot S+1, which is beyond the current forecast horizon.

**Execution:**

1. `rollForward` receives H → calls `checkTime` → calls `readLedgerState`.
2. `projectLedgerView` for H's slot returns `Nothing` (beyond forecast horizon).
3. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs`.
4. `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag`:
   - Empty snapshot → block-count comparison: `ourTip.blockNo = 100 > theirTip.blockNo = 99` → `ShouldNotSwitch`.
5. `throwSTM (CandidateTooSparse ...)` → node disconnects from peer.
6. Node remains on `C_local` (weight 100) instead of adopting `C_peer` (weight 104, the canonical chain under Peras).

**Expected behavior with fix:**

Step 4 would use the real snapshot → total weight comparison: `100 < 104` → `ShouldSwitch` → node stays connected, waits for forecast horizon to advance, then validates and adopts `C_peer`.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L174-182)
```haskell
    case NE.nonEmpty
      [ (chain, reason)
      | chain <- chains
      , ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
      ] of
      -- If there are no candidates, no chain selection is needed
      Nothing -> pure curChain
      Just chains' ->
        fromMaybe curChain <$> chainSelection' curChain chains'
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-433)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
```
