### Title
ChainSync Client Uses Empty Peras Weight Snapshot in `checkPreferTheirsOverOurs`, Causing Incorrect Peer Disconnection and Non-Canonical Chain Following — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when comparing a peer's candidate fragment against the node's current chain. This is structurally analogous to the reported vulnerability: a registry of boosted-block weights exists and is maintained (the `PerasCertDB`), but is deliberately excluded from a critical comparison step. When Peras is enabled, a peer serving a chain that is heavier by Peras total weight but shorter by raw block count will be incorrectly disconnected via `CandidateTooSparse`, preventing the node from ever adopting the canonical (heaviest) chain.

---

### Finding Description

`checkPreferTheirsOverOurs` is called inside the ChainSync client's header-processing loop to verify that the peer's candidate fragment is still preferable to the node's current chain. If it is not, the client throws `CandidateTooSparse` and terminates the connection. [1](#0-0) 

The comparison delegates to `preferAnchoredCandidate`, which accepts a `PerasWeightSnapshot` parameter. When Peras is active, this snapshot is the authoritative source of per-block weight boosts stored in the `PerasCertDB`: [2](#0-1) 

However, `checkPreferTheirsOverOurs` passes `emptyPerasWeightSnapshot` — an empty map — instead of reading the live snapshot: [3](#0-2) 

The actual chain-selection path (`chainSelectionForBlock`, `constructPreferableCandidates`) correctly reads the live snapshot from `cdbPerasCertDB`: [4](#0-3) 

The disconnect happens at the ChainSync header-validation stage, **before** blocks are downloaded and before real chain selection is ever invoked. The node therefore never reaches the code that would correctly weigh the candidate.

The `PerasWeightSnapshot` is computed on demand from `pcdsCertsByTicket` in the `PerasCertDB`: [5](#0-4) 

The `Fingerprint` on the snapshot is updated every time a new certificate is added: [6](#0-5) 

So the live weight state exists and is maintained, but `checkPreferTheirsOverOurs` is structurally isolated from it — the same "removed from the update loop but still has state" pattern as the reported TOKE-8 class.

---

### Impact Explanation

**Impact: High — Chain selection bug that lets an unprivileged peer cause an honest node to prefer a non-canonical chain.**

When Peras is enabled:

1. A node adopts chain C1 (block count 10, no Peras boost, total weight 10).
2. A Peras certificate is issued boosting a block on fork C2 (block count 9, boost +5, total weight 14). C2 is now the canonical chain.
3. An honest peer connects and begins serving C2 headers.
4. `checkPreferTheirsOverOurs` evaluates `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag`. With an empty snapshot, comparison is by block count only: C2 (9) < C1 (10) → `ShouldNotSwitch`.
5. The client throws `CandidateTooSparse` and disconnects from the honest peer.
6. The node remains permanently on C1, the non-canonical chain.

An adversary who first serves C1 (a longer-by-block-count but lighter chain) to the node can then rely on this bug to ensure the node is subsequently unable to adopt the heavier canonical chain C2 from any honest peer.

The `WeightedSelectView` and `preferCandidate` logic correctly implement Peras-aware comparison: [7](#0-6) 

But this logic is bypassed entirely in `checkPreferTheirsOverOurs` because the snapshot is empty.

---

### Likelihood Explanation

**Likelihood: Medium** (conditional on Peras being enabled).

- Peras is currently disabled by default; the bug is dormant until Peras is activated on a network.
- Once Peras is active, the scenario requires only that a Peras certificate boosts a block on a fork that is shorter by raw block count than the node's current chain — a normal occurrence during any Peras round where the boosted block is not on the longest-by-count chain.
- No special privileges, key material, or stake majority are required. Any peer can trigger the disconnection simply by serving valid headers for the heavier chain.
- The attack is repeatable: every time an honest peer reconnects and serves the heavier chain, the node will disconnect again.

---

### Recommendation

1. **Immediate**: Pass the live `PerasWeightSnapshot` (obtained from `cdbPerasCertDB` via `getWeightSnapshot`) into `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`. The snapshot is already available as an `STM` action on the `ChainDB` API: [8](#0-7) 

2. **Long-term**: The existing TODO comment acknowledges the check should be removed entirely (issue #64). Until removal, the snapshot must be live. Removing the check is the cleaner fix because `checkPreferTheirsOverOurs` duplicates logic already present in the main chain-selection path, which already uses the correct snapshot.

---

### Proof of Concept

```
Setup (Peras enabled, boost B = 5, k = 2160):

  Adversary peer A serves:
    C1: [genesis] → B1 → B2 → ... → B10   (block count 10, no boost, weight 10)

  Node adopts C1 via normal chain selection (C1 is longest).

  Peras certificate issued for round R, boosting block B9' on fork C2:
    C2: [genesis] → B1 → B2 → ... → B8 → B9'  (block count 9, boost 5, weight 14)

  Honest peer H connects and sends C2 headers.

  ChainSync client calls checkPreferTheirsOverOurs:
    preferAnchoredCandidate cfg emptyPerasWeightSnapshot C1_frag C2_frag
    → compares block count: 9 < 10 → ShouldNotSwitch
    → throwSTM (CandidateTooSparse ...)
    → H is disconnected.

  Node remains on C1 (weight 10) despite C2 (weight 14) being canonical.
  Any subsequent honest peer serving C2 is also disconnected.
  Adversary's non-canonical chain C1 is permanently selected.
``` [1](#0-0) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-201)
```haskell
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-210)
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
```
