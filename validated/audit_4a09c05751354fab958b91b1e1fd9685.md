### Title
Stale Peras Weight State in `checkPreferTheirsOverOurs` Causes Incorrect Chain Selection Beyond Forecast Horizon - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when comparing the candidate chain against the local selection at the forecast-horizon boundary. Every other chain-selection call site reads the live `PerasWeightSnapshot` from the `PerasCertDB`. This missing state read is the direct analog of the reported "sync not called" class: a state that is correctly consulted in most code paths is silently omitted in one specific path, causing the node to make chain-selection decisions based on stale (empty) weight data.

---

### Finding Description

When a peer sends a header whose slot is beyond the current forecast horizon, the ChainSync client calls `checkPreferTheirsOverOurs` to decide whether to keep waiting (the candidate is still preferable) or disconnect (`CandidateTooSparse`). [1](#0-0) 

The comparison is performed via `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot` argument. At this call site the snapshot is unconditionally `emptyPerasWeightSnapshot`: [2](#0-1) 

The code even carries an explicit `TODO` acknowledging the problem (referencing issue #64). By contrast, every other production call site that performs chain comparison reads the live snapshot. For example, the NodeKernel's GSM view reads `weights` from `getPerasWeightSnapshot` before calling `preferAnchoredCandidate`: [3](#0-2) 

And `switchTo` in ChainSel reads the live snapshot before committing a fork: [4](#0-3) 

The `PerasWeightSnapshot` is the authoritative record of which blocks have been boosted by Peras certificates. When Peras is active, a block's effective chain weight is `block_count + Σ(certificate_boosts)`. Ignoring boosts in `checkPreferTheirsOverOurs` means the comparison degrades to pure block-count comparison, which is incorrect under Peras. [5](#0-4) 

---

### Impact Explanation

Two concrete failure modes arise when Peras is enabled:

**Mode A – Premature disconnection from an honest peer serving a heavier chain.**  
If the honest candidate chain is shorter in block count but heavier in Peras weight (a certificate has boosted one of its blocks), `checkPreferTheirsOverOurs` with empty weights concludes the candidate is not preferable and throws `CandidateTooSparse`. The node disconnects from the honest peer and remains on the lighter (less-secure) chain. This is a chain-selection error: the node prefers a non-canonical chain beyond the intended security assumptions.

**Mode B – Failure to disconnect from an adversarial peer serving a lighter chain.**  
If an adversary's chain is longer in block count but lighter in Peras weight (the honest chain has accumulated certificate boosts the adversary's chain lacks), `checkPreferTheirsOverOurs` with empty weights sees the adversary's chain as preferable (longer) and keeps the connection open. The node continues processing the adversary's headers and may eventually adopt the lighter chain.

Both modes violate the Peras chain-selection invariant: the node should always prefer the chain with the highest total weight.

---

### Likelihood Explanation

- Peras is currently disabled by default (`emptyPerasWeightSnapshot` is the no-op fast path in `preferAnchoredCandidate`), so the bug is dormant on mainnet today.
- Once Peras is enabled on a private testnet or production network, the bug is reachable by any unprivileged peer: sending headers beyond the forecast horizon is a normal protocol operation and requires no special privileges or key material.
- The forecast horizon is exceeded routinely during initial sync and whenever a peer is significantly ahead of the local chain, making the vulnerable code path frequently exercised.
- The `TODO` comment and linked issue confirm the developers are aware but have not yet resolved it.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live snapshot read from the `PerasCertDB`, consistent with every other chain-comparison call site. The `ChainDbView` record already exposes `getPerasWeightSnapshot` as an STM action, so the fix is a single additional STM read inside the existing `atomically` block:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot  -- read live snapshot
  if shouldSwitch $ preferAnchoredCandidate (configBlock cfg) weights ourFrag theirFrag
    then pure ()
    else throwSTM $ CandidateTooSparse ...
```

`getPerasWeightSnapshot` is already available in the `ChainDbView` used by the ChainSync client: [6](#0-5) 

---

### Proof of Concept

1. Enable Peras on a private testnet (set `eraPerasRoundLength` to a non-zero value).
2. Issue a Peras certificate boosting block `B` on chain `C_heavy` (shorter in block count, heavier in weight).
3. Connect a peer serving `C_heavy` whose tip is beyond the local forecast horizon.
4. Observe that `checkPreferTheirsOverOurs` fires with `emptyPerasWeightSnapshot`, computes `ShouldNotSwitch` (because `C_heavy` is shorter), and throws `CandidateTooSparse`.
5. The node disconnects from the honest peer and retains the lighter chain `C_light`.
6. Repeat with the live snapshot: `preferAnchoredCandidate` now returns `ShouldSwitch` and the node stays connected, eventually adopting `C_heavy`.

The root cause is confirmed at: [7](#0-6)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs (L301-311)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L899-929)
```haskell
switchTo CDB{..} weights triggerPt chainDiff reason = MkSuccessForkerAction $ \forker -> do
  traceWith addBlockTracer $
    ChangingSelection $
      castPoint $
        Diff.getTip chainDiff
  (curChain, newChain, events, prevTentativeHeader, newLedger, closeOrphanedStates) <- atomically $ do
    InternalChain curChain curChainWithTime <- readTVar cdbChain -- Not Query.getCurrentChain!
    curLedger <- getVolatileTip cdbLedgerDB
    newLedger <- forkerGetLedgerState forker
    case Diff.apply curChain chainDiff of
      -- Impossible, as described in the docstring
      Nothing ->
        error "chainDiff doesn't fit onto current chain"
      Just newChain -> do
        let lcfg = configLedger cdbTopLevelConfig
            diffWithTime =
              -- the new ledger state can translate the slots of the new
              -- headers
              Diff.map
                ( mkHeaderWithTime
                    lcfg
                    (ledgerState newLedger)
                )
                chainDiff
            newChainWithTime =
              case Diff.apply curChainWithTime diffWithTime of
                Nothing -> error "chainDiff failed for HeaderWithTime"
                Just x -> x

        writeTVar cdbChain $ InternalChain newChain newChainWithTime
        closeOrphanedStates <- forkerCommit forker
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```
