### Title
ChainSync Client Uses Empty Peras Weight Context for Chain Preference Check, Ignoring Certificate Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

`checkPreferTheirsOverOurs` in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when calling `preferAnchoredCandidate`, stripping all Peras certificate boosts from the chain-preference comparison. Every other production call-site reads the live snapshot from the ChainDB. When Peras is active, this causes the node to evaluate "is the peer's chain better than ours?" using only raw block-count/`selectView`, exactly as if Peras did not exist — the direct analog of using the base `Context._msgSender()` instead of `ERC2771Context._msgSender()`.

---

### Finding Description

`preferAnchoredCandidate` has two code paths gated on `isEmptyPerasWeightSnapshot weights`:

- **Empty weights** → falls back to the plain Praos longest-chain rule (`selectView` on the tip headers).
- **Non-empty weights** → uses `weightedSelectView` over the full suffix, incorporating Peras certificate boosts. [1](#0-0) 

Every production call-site that performs chain comparison reads the live snapshot:

- `BlockFetch/ClientInterface.hs` calls `getPerasWeightSnapshot chainDB` and passes the result to `preferAnchoredCandidate`.
- `NodeKernel.hs` calls `ChainDB.getPerasWeightSnapshot chainDB` for the GSM candidate-over-selection check.
- `ChainSel.hs` receives `weights` as a parameter threaded from the ChainDB. [2](#0-1) [3](#0-2) 

The single exception is `checkPreferTheirsOverOurs`, which hardcodes `emptyPerasWeightSnapshot`:

```haskell
preferAnchoredCandidate
  (configBlock cfg)
  -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
  emptyPerasWeightSnapshot   -- ← always empty; ignores live Peras boosts
  ourFrag
  theirFrag
``` [4](#0-3) 

`checkPreferTheirsOverOurs` is invoked precisely when a peer's header is **beyond the forecast horizon** — the node cannot yet validate the header and must decide whether to keep or drop the connection. If the peer's chain is not preferred, the node throws `CandidateTooSparse` and disconnects. [5](#0-4) 

---

### Impact Explanation

When Peras is active and certificate boosts are present, the comparison in `checkPreferTheirsOverOurs` is evaluated with the wrong context:

**Scenario — honest peer disconnected, adversarial peer retained:**

1. The canonical chain has Peras certificate boosts; by weighted measure it is preferred, but it is shorter by raw block count.
2. An adversary presents a longer-by-block-count chain with no Peras boosts, with headers beyond the forecast horizon.
3. `checkPreferTheirsOverOurs` with empty weights sees the adversary's chain as `ShouldSwitch` (longer) → keeps the adversary's connection.
4. Honest peers present the Peras-boosted canonical chain, also with headers beyond the forecast horizon.
5. `checkPreferTheirsOverOurs` with empty weights sees the honest chain as `ShouldNotSwitch` (shorter by block count) → throws `CandidateTooSparse` → disconnects from honest peers.
6. The node is left tracking only the adversary's non-canonical chain and, once the forecast horizon advances, selects it.

This is a **chain selection error**: an unprivileged peer can cause an honest node to prefer a non-canonical, less-secure chain beyond the intended Peras security assumptions.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

- Requires Peras to be active and certificate boosts to be present on the canonical chain.
- Requires the peer's headers to be beyond the forecast horizon (a normal operating condition during sync or after a slot gap).
- The attacker needs only to present a longer-by-block-count chain; no key material or privileged access is required.
- The TODO comment (`https://github.com/tweag/cardano-peras/issues/64`) confirms the developers are aware the check is inconsistent with Peras, but the fix has not yet been applied.

Likelihood: **Medium** — conditional on Peras activation; trivially triggerable by any peer once Peras is live.

---

### Recommendation

Replace the hardcoded `emptyPerasWeightSnapshot` with the live snapshot read from the ChainDB, consistent with every other call-site:

```haskell
-- Before (incorrect):
preferAnchoredCandidate (configBlock cfg) emptyPerasWeightSnapshot ourFrag theirFrag

-- After (correct):
weights <- lift $ ChainDB.getPerasWeightSnapshot chainDB
preferAnchoredCandidate (configBlock cfg) (forgetFingerprint weights) ourFrag theirFrag
```

Alternatively, if the intent is to remove the check entirely (as the TODO suggests), do so promptly and track the issue to closure. Leaving the check in place with the wrong context is strictly worse than removing it.

---

### Proof of Concept

1. Activate Peras on a private testnet so that certificate boosts are issued for blocks on the canonical chain.
2. Run an honest node `N` whose canonical chain has Peras boosts and is shorter by raw block count than an adversarial fork.
3. Connect an adversarial peer `A` presenting the longer-by-block-count fork with headers beyond `N`'s forecast horizon.
4. Connect an honest peer `H` presenting the Peras-boosted canonical chain, also with headers beyond `N`'s forecast horizon.
5. Observe that `N` disconnects from `H` (`CandidateTooSparse`) while retaining `A`'s connection.
6. Once the forecast horizon advances, `N` selects `A`'s non-canonical chain.

The root cause is confirmed at: [6](#0-5) [1](#0-0) [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-241)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
          }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1801-1819)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
