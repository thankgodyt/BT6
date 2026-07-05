### Title
Peras Weight Check Missing in ChainSync `checkPreferTheirsOverOurs`, Present in All Other Chain-Selection Paths — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when calling `preferAnchoredCandidate`, while every other chain-selection call site passes the real Peras weight snapshot. This is a direct structural analog to the reported bug: a cap/limit check that is correctly enforced in one code path is silently absent in a parallel path that should enforce the same invariant.

---

### Finding Description

When a peer's header is beyond the forecast horizon, `readLedgerStateHelper` calls `checkPreferTheirsOverOurs` to decide whether to disconnect from that peer. [1](#0-0) 

Inside `checkPreferTheirsOverOurs`, `preferAnchoredCandidate` is called with a hardcoded `emptyPerasWeightSnapshot`: [2](#0-1) 

The `emptyPerasWeightSnapshot` constant strips all Peras certificate boost weights from the comparison, reducing it to a pure chain-length comparison. The TODO comment on line 1841 explicitly acknowledges this is wrong and references an open issue.

By contrast, every other call site that invokes `preferAnchoredCandidate` passes the real `weights` (Peras weight snapshot):

- **Initial chain selection** in `ChainSel.hs`: [3](#0-2) 

- **Ongoing chain selection** in `ChainSel.hs`: [4](#0-3) 

- **Block fetch plausibility check** in `BlockFetch/ClientInterface.hs`: [5](#0-4) 

`preferAnchoredCandidate` itself branches on whether the weight snapshot is empty: when non-empty it computes a `weightedSelectView` over the suffix fragments; when empty it falls back to a tip-only `selectView` comparison (pure block number / VRF tiebreaker). [6](#0-5) 

---

### Impact Explanation

Consider the following scenario once Peras is active:

1. The canonical chain `C_peras` is **shorter** by block count but carries a valid Peras certificate that boosts one of its blocks, making it the Peras-weight-preferred chain.
2. An adversarial chain `C_long` is **longer** by block count but carries no Peras certificate.
3. A victim node receives headers from both peers. For the peer serving `C_peras`, the next header falls beyond the forecast horizon, triggering `checkPreferTheirsOverOurs`.
4. Because `emptyPerasWeightSnapshot` is used, the comparison is purely by chain length. `C_peras` is shorter → `shouldSwitch` returns `False` → the node throws `CandidateTooSparse` and **disconnects** from the peer serving the canonical chain.
5. The peer serving `C_long` is not disconnected (their chain is longer under the empty-weight comparison).
6. The node downloads and validates `C_long`. The actual chain selection in `ChainSel.hs` uses real weights, but if no other peer is serving `C_peras`, the node permanently adopts the non-canonical chain.

This is a chain-selection manipulation: an unprivileged peer presenting a longer chain can cause an honest node to sever its connection to the peer serving the Peras-preferred canonical chain, leading the node to adopt the wrong chain.

---

### Likelihood Explanation

- Requires Peras to be active and a valid Peras certificate to exist on the canonical chain (a normal operational condition once Peras is deployed).
- The attacker needs only to be a peer presenting a longer chain — no key material, stake, or privileged access is required.
- The trigger condition (header beyond the forecast horizon) is a normal occurrence during syncing or when a peer is slightly ahead.
- The node must have no other peer serving the Peras-preferred chain at that moment, which is plausible in a targeted eclipse or during initial sync.

---

### Recommendation

Pass the real `PerasWeightSnapshot` into `checkPreferTheirsOverOurs` instead of `emptyPerasWeightSnapshot`, mirroring every other call site. The `ConfigEnv` or `DynamicEnv` already carries the weight snapshot; it should be threaded into this function. The referenced TODO (`https://github.com/tweag/cardano-peras/issues/64`) proposes removing the check entirely — if that is the chosen resolution, the check must be removed before Peras activates on mainnet, not left in its current broken state.

---

### Proof of Concept

**Broken path** — `checkPreferTheirsOverOurs` (ChainSync client):

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        emptyPerasWeightSnapshot   -- ← Peras weights silently dropped
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
```

**Correct path** — `initialChainSelection` (ChainDB):

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs
[ (chain, reason)
| chain <- chains
, ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
--                                                      ^^^^^^^ real Peras weights used
]
```

The structural mismatch is identical to the reported Solidity bug: the "standard" processing path (`checkPreferTheirsOverOurs`) omits the cap/weight check that the "instant" processing path (actual chain selection) correctly enforces.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1817)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L174-178)
```haskell
    case NE.nonEmpty
      [ (chain, reason)
      | chain <- chains
      , ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
      ] of
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L262-284)
```haskell
    plausibleCandidateChain weights ours cand =
      -- 1. The ChainDB maintains the invariant that the anchor of our fragment
      --    corresponds to the immutable tip.
      --
      -- 2. The ChainSync client locally maintains the invariant that our
      --    fragment and the candidate fragment have the same anchor point. This
      --    establishes the precondition required by @preferAnchoredCandidate@.
      --
      -- 3. However, by the time that the BlockFetch logic processes a fragment
      --    presented to it by the ChainSync client, our current fragment might
      --    have changed, and they might no longer be anchored at the same
      --    point. This means that we are no longer guaranteed that the
      --    precondition holds.
      --
      -- 4. Therefore, we check whether the candidate fragments still intersects
      --    with our fragment; if not, then it is only a matter of time until the
      --    ChainSync client disconnects from that peer.
      case AF.intersectionPoint ours cand of
        -- REVIEW: Hmm, maybe we want to change 'preferAnchoredCandidates' to
        -- also just return 'False' in this case (and we remove the
        -- precondition).
        Nothing -> False
        Just _ -> shouldSwitch $ preferAnchoredCandidate bcfg weights ours cand
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
