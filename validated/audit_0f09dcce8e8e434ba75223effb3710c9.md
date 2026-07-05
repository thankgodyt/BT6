### Title
Stale Weight Snapshot in `checkPreferTheirsOverOurs` Causes Incorrect Chain-Selection Disconnection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The ChainSync client's `checkPreferTheirsOverOurs` guard evaluates chain preference using a hardcoded `emptyPerasWeightSnapshot` instead of the live Peras weight snapshot. This is a direct check-before-effect ordering analog: the guard checks a threshold on incorrect (empty) state rather than the actual post-certificate state, causing the node to disconnect from peers whose chain is heavier under real Peras weights but shorter in raw block count.

---

### Finding Description

In `chainSelectionForBlock`, the real Peras weight snapshot is read atomically and used for all chain-selection comparisons: [1](#0-0) 

However, the ChainSync client's `checkPreferTheirsOverOurs` guard — which decides whether to throw `CandidateTooSparse` and disconnect from a peer — explicitly passes `emptyPerasWeightSnapshot` to `preferAnchoredCandidate`: [2](#0-1) 

The `preferAnchoredCandidate` function, when given a non-empty weight snapshot, computes the weighted total of each chain's suffix (block count + Peras certificate boosts). With `emptyPerasWeightSnapshot`, it degrades to a pure block-count comparison: [3](#0-2) 

The `PerasWeightSnapshot` is populated by `PerasCertDB.getWeightSnapshot`, which reflects all certificate boosts for blocks in the volatile window: [4](#0-3) 

The `SecurityParam` in Peras is explicitly defined as a *weight* bound, not a block-count bound: [5](#0-4) 

The developers have acknowledged this is wrong with a TODO comment referencing issue #64, but the code remains in production: [6](#0-5) 

---

### Impact Explanation

**Concrete scenario:**

- Our chain: blocks A→B→C→D→E (5 blocks, no Peras boosts, total weight = 5)
- Peer's chain: blocks A→B→C (3 blocks, Peras certificate boosts block C by weight 3, total weight = 6)

With `emptyPerasWeightSnapshot`, `checkPreferTheirsOverOurs` computes peer weight = 3 < our weight = 5 → throws `CandidateTooSparse` → node disconnects from the peer.

With the real weight snapshot, peer weight = 6 > our weight = 5 → the peer's chain is the canonical chain and the node should switch.

The node is thus persistently disconnected from peers offering the canonical (heavier) Peras-boosted chain and remains on a lighter, non-canonical fork. This violates the Peras chain-selection invariant that the heaviest chain wins.

**Impact class:** High — chain-selection bug that causes an honest node to reject the canonical chain and stay on a less-secure fork, triggered by any unprivileged peer serving a legitimately Peras-boosted chain.

---

### Likelihood Explanation

Peras is designed so that certificate boosts can make a shorter chain heavier than a longer one. This is the entire point of the weight-based chain selection. Any honest peer that has received Peras certificates boosting blocks on a fork shorter (in block count) than our current selection will trigger this bug. No adversarial stake, key compromise, or privileged access is required — the peer only needs to serve a valid Peras-boosted chain fragment via the standard ChainSync mini-protocol.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` read from `getPerasWeightSnapshot`. The check should use the same weight snapshot as `chainSelectionForBlock` to ensure the two are consistent. The existing TODO comment (`-- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64`) confirms the developers intend to address this; the fix should either remove the check entirely (as the TODO suggests) or replace `emptyPerasWeightSnapshot` with the real snapshot so the guard and the actual chain-selection logic agree on which chain is heavier.

---

### Proof of Concept

1. Node N is on chain `A→B→C→D→E` (5 blocks, weight 5, no Peras certs).
2. Peer P has chain `A→B→C` where block C carries a Peras certificate boost of weight 3 (total weight 6).
3. P connects to N via ChainSync and advertises its tip at C.
4. N's `checkPreferTheirsOverOurs` calls `preferAnchoredCandidate cfg emptyPerasWeightSnapshot ourFrag theirFrag`.
5. With empty weights, `theirFrag` has block-count weight 3 < `ourFrag` block-count weight 5 → `ShouldNotSwitch` → `throwSTM CandidateTooSparse`.
6. N disconnects from P.
7. N remains on the lighter chain (weight 5) and never adopts the canonical chain (weight 6).
8. Every reconnection attempt by P repeats steps 3–7 indefinitely, as long as P's chain remains shorter in block count than N's chain. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L167-213)
```haskell
preferAnchoredCandidate ::
  forall blk h h'.
  ( BlockSupportsProtocol blk
  , HasCallStack
  , GetHeader1 h
  , GetHeader1 h'
  , HeaderHash (h blk) ~ HeaderHash blk
  , HeaderHash (h blk) ~ HeaderHash (h' blk)
  , HasHeader (h blk)
  , HasHeader (h' blk)
  ) =>
  BlockConfig blk ->
  -- | Peras weights used to judge this chain.
  PerasWeightSnapshot blk ->
  -- | Our chain
  AnchoredFragment (h blk) ->
  -- | Candidate
  AnchoredFragment (h' blk) ->
  ShouldSwitch (ReasonForSwitch' blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-44)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
  deriving (Eq, Generic, NoThunks, ToCBOR, FromCBOR)
  deriving Show via Quiet SecurityParam

-- | The maximum amount of weight we can roll back.
maxRollbackWeight :: SecurityParam -> PerasWeight
maxRollbackWeight = PerasWeight . unNonZero . maxRollbacks
```
