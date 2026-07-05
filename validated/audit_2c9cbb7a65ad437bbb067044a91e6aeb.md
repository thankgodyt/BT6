### Title
Chain Selection Disconnection Uses Empty Peras Weight Snapshot — Intermediate-State Check Causes Incorrect Peer Rejection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client evaluates whether a candidate chain is preferable to the local selection using `emptyPerasWeightSnapshot` — an empty weight map that ignores all Peras certificate boosts — instead of the actual live `PerasWeightSnapshot`. This is structurally identical to the Ajna M-2 bug: a validity check is performed against an incomplete intermediate state (no weights) rather than the final state (actual weights), causing a valid operation (maintaining a connection to a peer offering the canonical heavier chain) to be incorrectly rejected.

---

### Finding Description

When the ChainSync client receives a header that is beyond the current forecast horizon, it cannot yet obtain a `LedgerView` to validate the header. It blocks in `readLedgerStateHelper`, retrying until the forecast horizon advances. Before retrying, it calls `checkPreferTheirsOverOurs` to decide whether to keep waiting or disconnect:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always empty; ignores all Peras boosts
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
``` [1](#0-0) 

`preferAnchoredCandidate` with an empty snapshot falls into the `isEmptyPerasWeightSnapshot` branch and compares chains purely by block number (`SelectView`/`BlockNo`):

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- compares only by BlockNo / TiebreakerView, ignoring all certificate boosts
      ...
  | otherwise =
      -- uses weightedSelectView: BlockNo + PerasWeight
      ...
``` [2](#0-1) 

The actual live weight snapshot is available from the ChainDB via `getPerasWeightSnapshot` and is used correctly everywhere else in the chain-selection pipeline — for example in `constructPreferableCandidates` and `chainSelection`: [3](#0-2) 

The `PerasWeightSnapshot` is built from `ValidatedPerasCert` entries stored in `PerasCertDB` and reflects the cumulative boost of all known certificates: [4](#0-3) 

In Peras, the canonical chain is the one with the highest **total weight** = `BlockNo + ΣPerasBoosts`. A candidate chain with fewer blocks but enough certificate boosts can be heavier than the local selection. When `checkPreferTheirsOverOurs` evaluates this candidate using `emptyPerasWeightSnapshot`, it sees only the block count, judges the candidate as not preferable, and disconnects the peer — even though the candidate represents the canonical chain.

---

### Impact Explanation

**High — Chain selection bug that causes an honest node to prefer a non-canonical, lighter chain over the canonical Peras-weighted chain.**

A node that has adopted a chain with more blocks but fewer Peras boosts will, when a peer offers the canonical heavier chain whose tip is beyond the forecast horizon, call `checkPreferTheirsOverOurs`, judge the candidate as not preferable (because block count alone is lower), and disconnect. The node then remains on the lighter non-canonical chain. Because the same check fires on every reconnect attempt, the node is persistently unable to adopt the canonical chain from any peer whose tip is beyond the forecast horizon at the time of the check. This violates the chain-selection invariant that the node must always prefer the chain with the highest total weight.

---

### Likelihood Explanation

**Medium.** The scenario requires:
1. Peras certificates to be in circulation (Peras deployed and active).
2. A candidate chain whose Peras boost makes it heavier than the local selection despite having fewer blocks — a realistic outcome after a round of voting that boosts a fork.
3. The candidate's tip to be beyond the local forecast horizon at the moment the check fires — a transient but recurring condition during normal syncing.

All three conditions are realistic in a live Peras network. The TODO comment at line 1841 (`-- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64`) confirms the developers have identified this as a known defect. [5](#0-4) 

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` read from the ChainDB (the same snapshot already threaded through `constructPreferableCandidates` and `chainSelection`). The ChainDB exposes this via `getPerasWeightSnapshot`: [6](#0-5) 

Alternatively, if the intent is to remove the check entirely (as the TODO suggests), do so — but only after confirming that the Genesis density check or another mechanism covers the case this check was guarding against.

---

### Proof of Concept

**Setup:** Peras is active. The local node holds chain `C_local` with 100 blocks and 0 Peras boosts (total weight = 100). A peer holds chain `C_peer` with 98 blocks and a Peras boost of 5 on one block (total weight = 103). `C_peer` is the canonical chain.

**Trigger sequence:**
1. The peer sends header `H` at slot `s` where `s` is beyond the local forecast horizon.
2. `readLedgerStateHelper` calls `checkPreferTheirsOverOurs`.
3. `preferAnchoredCandidate ... emptyPerasWeightSnapshot ourFrag theirFrag` compares `BlockNo 100` vs `BlockNo 98` → `ShouldNotSwitch GT`.
4. `checkPreferTheirsOverOurs` throws `CandidateTooSparse`, disconnecting the peer.
5. The node remains on `C_local` (weight 100) and never adopts `C_peer` (weight 103).

The same outcome repeats on every reconnect as long as the peer's tip remains beyond the forecast horizon, permanently preventing adoption of the canonical chain. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L762-777)
```haskell
              . NE.filter (not . Diff.rollbackExceedsSuffix weights curChain)
              -- Extend the diff with candidates fitting on @p@
              . Paths.extendWithSuccessors succsOf lookupBlockInfo
              $ diff
        -- We cannot reach the block from the current selection.
        | otherwise -> pure []
  let fragments =
        -- Trim fragments so that they follow the LoE, that is, they extend the LoE
        -- by at most @k@ blocks or are extended by the LoE.
        fmap (trimToLoE loeFrag) $
          diffs
  pure
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
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
