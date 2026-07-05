### Title
Incorrect Peras Weight Used in ChainSync Forecast-Horizon Disconnect Check — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

When a peer's header arrives beyond the forecast horizon, the ChainSync client calls `checkPreferTheirsOverOurs` to decide whether to disconnect. This check calls `preferAnchoredCandidate` with a hard-coded `emptyPerasWeightSnapshot` instead of the actual Peras weight snapshot. As a result, the comparison ignores all Peras weight boosts and reduces to a pure block-count comparison. A candidate chain that is heavier than the local chain due to Peras boosts — but not longer by block count — will be incorrectly judged as non-preferable, causing the node to disconnect from the peer offering the canonical (heavier) chain.

---

### Finding Description

In `checkPreferTheirsOverOurs`:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always zero; ignores actual Peras boosts
        ourFrag
        theirFrag =
    pure ()
  | otherwise =
      throwSTM $
        CandidateTooSparse ...
```

`preferAnchoredCandidate` dispatches on whether the weight snapshot is empty:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- non-Peras path: compares only svBlockNo then tiebreaker
      ...
  | otherwise =
      -- Peras path: intersects fragments, computes wsvTotalWeight = blockNo + weightBoost
      ...
```

Because `emptyPerasWeightSnapshot` is always passed, the Peras path is never taken. `wsvTotalWeight` is never computed; only `svBlockNo` (and the tiebreaker) is used. This is structurally identical to the external report's root cause: a protection parameter (`minMarketTokenAmt`) was computed from the user's initial deposit value rather than the actual leveraged deposit value, making the protection weaker than intended. Here, the protection check (disconnect guard) is computed from zero weights rather than the actual Peras weights, making the guard incorrect.

The actual chain-selection code in `ChainSel.hs` correctly uses the real snapshot:

```haskell
. NE.filter (not . Diff.rollbackExceedsSuffix weights curChain)
...
ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
```

Only the ChainSync client's forecast-horizon guard uses the empty snapshot.

---

### Impact Explanation

When Peras is active, consider:

- **Our chain**: suffix after intersection has block number N, Peras boost B₁.
- **Peer's chain**: suffix after intersection has block number N, Peras boost B₂ > B₁ (heavier, canonical chain).

With actual weights, `wsvTotalWeight` of the peer's suffix = N + B₂ > N + B₁ = ours → `ShouldSwitch` → node keeps the connection.

With `emptyPerasWeightSnapshot`, both sides have `wsvTotalWeight = N` → comparison falls to the tiebreaker (VRF output). If the tiebreaker favors our chain, `ShouldNotSwitch` → node throws `CandidateTooSparse` and disconnects from the peer offering the canonical chain.

The node then fails to adopt the heavier canonical chain from this peer. If all peers offering the canonical chain are beyond the forecast horizon simultaneously (e.g., during initial sync), the node may adopt a lighter non-canonical chain from a different peer, constituting a chain selection failure beyond the intended security assumptions.

**Impact class**: High — chain selection bug that can cause an honest node to prefer a non-canonical, less-secure chain when Peras is active.

---

### Likelihood Explanation

- Requires Peras to be active (currently in development, targeted for production deployment).
- Requires a peer's headers to be beyond the forecast horizon (normal during initial sync or after a long network partition).
- Requires the canonical chain to be heavier by Peras weight but not longer by block count (a realistic scenario when a Peras certificate boosts a block on the canonical chain).
- The TODO comment at the call site (`https://github.com/tweag/cardano-peras/issues/64`) confirms the developers are aware the check is broken under Peras.

**Likelihood**: Medium — the conditions are realistic once Peras is deployed, and the entry path (sending headers beyond the forecast horizon) requires no special privileges.

---

### Recommendation

Pass the actual `PerasWeightSnapshot` to `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`. The snapshot is already available in the `ChainSelEnv` / `ChainDbEnv` context and is used correctly in `constructPreferableCandidates`. The ChainSync client's `ConfigEnv` or `DynamicEnv` should be extended to carry the live snapshot (or a read-only STM reference to it), mirroring how `constructPreferableCandidates` receives `weights`:

```haskell
-- Current (incorrect):
emptyPerasWeightSnapshot

-- Corrected:
actualWeights  -- obtained from the same source as ChainSel.hs uses
```

Alternatively, if the check is to be removed entirely (as the TODO suggests), it should be removed before Peras is activated on any network where Peras boosts are non-zero.

---

### Proof of Concept

1. Activate Peras on a private testnet so that at least one block receives a non-zero boost B.
2. Run an honest node whose current chain tip has block number N and Peras boost B₁ = 0.
3. Connect a peer whose chain has block number N and Peras boost B₂ = B > 0 (canonical, heavier chain), but whose next header is beyond the forecast horizon of the honest node.
4. Observe that `checkPreferTheirsOverOurs` calls `preferAnchoredCandidate` with `emptyPerasWeightSnapshot`; both chains compare as equal by block number; the tiebreaker (VRF) may favor the honest node's chain.
5. The honest node throws `CandidateTooSparse` and disconnects from the peer offering the heavier canonical chain.
6. The honest node retains its lighter chain and does not adopt the canonical chain from this peer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L759-777)
```haskell
              -- Filter out candidates that have less weight than the current
              -- chain. We don't want to needlessly read the headers from disk
              -- for those candidates.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Fragment/Diff.hs (L74-98)
```haskell
-- | Return 'True' iff applying the 'ChainDiff' to the given chain @C@ will
-- result in a chain with less weight than @C@, i.e., the suffix of @C@ to roll
-- back has more weight than suffix is adding.
rollbackExceedsSuffix ::
  forall b0 b1 b2.
  ( HasHeader b0
  , HasHeader b1
  , HasHeader b2
  , HeaderHash b0 ~ HeaderHash b1
  , HeaderHash b0 ~ HeaderHash b2
  ) =>
  PerasWeightSnapshot b0 ->
  -- | The chain @C@ the diff is applied to.
  AnchoredFragment b1 ->
  ChainDiff b2 ->
  Bool
rollbackExceedsSuffix weights curChain (ChainDiff nbRollback suffix) =
  weightOf suffixToRollBack > weightOf suffix
 where
  suffixToRollBack = AF.anchorNewest nbRollback curChain

  weightOf ::
    (HasHeader b, HeaderHash b ~ HeaderHash b0) =>
    AnchoredFragment b -> PerasWeight
  weightOf = totalWeightOfFragment weights
```
