### Title
`checkPreferTheirsOverOurs` Uses `emptyPerasWeightSnapshot`, Causing Incorrect Chain-Selection Disconnect Under Peras — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs`)

---

### Summary

The `checkPreferTheirsOverOurs` function in the ChainSync client hardcodes `emptyPerasWeightSnapshot` when deciding whether to disconnect from a peer whose header is beyond the forecast horizon. When Peras is active, this ignores all Peras weight boosts and compares chains purely by block count. A candidate chain that is shorter by block number but heavier by Peras total weight — i.e., the canonically preferred chain under Peras rules — is incorrectly judged as non-preferred, causing the node to disconnect from the peer serving it and remain on the lighter chain.

---

### Finding Description

The ChainSync client calls `checkPreferTheirsOverOurs` inside `readLedgerStateHelper` whenever the ledger-state projection returns `Nothing` (forecast horizon exceeded):

```haskell
case prj lst of
  Nothing -> do
    checkPreferTheirsOverOurs kis'
    retry
  Just ledgerView ->
    return $ return $ Intersects kis' ledgerView
``` [1](#0-0) 

The function itself is:

```haskell
checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← hardcoded empty snapshot
        ourFrag
        theirFrag =
      pure ()
  | otherwise =
      throwSTM $ CandidateTooSparse ...
``` [2](#0-1) 

`preferAnchoredCandidate` dispatches on whether the weight snapshot is empty. When it is empty, it falls into the non-Peras path and compares chains purely by `SelectView` (block number):

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- non-Peras path: compare by block number only
      ...
  | otherwise =
      -- Peras path: compare by total weight (blockNo + weightBoost)
      ...
``` [3](#0-2) 

Under Peras, `wsvTotalWeight = blockNo + weightBoost`. A chain that is shorter by block count but carries a large Peras boost can be strictly heavier:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

The actual Peras weight snapshot is available via `getPerasWeightSnapshot` on the ChainDB and is correctly used everywhere else in chain selection: [5](#0-4) 

The `readChainComparison` in BlockFetch correctly reads the live snapshot: [6](#0-5) 

But `checkPreferTheirsOverOurs` never reads it — it always passes `emptyPerasWeightSnapshot`.

---

### Impact Explanation

**Vulnerability class**: Chain-selection error — incorrect state (stale/empty weight snapshot) used at a critical decision point, causing the node to disconnect from a peer serving the canonically preferred chain.

**Concrete impact**: When Peras is active and a candidate chain `C_cand` satisfies:

- `blockNo(C_cand) < blockNo(C_ours)` (shorter by block count), but
- `blockNo(C_cand) + weightBoost(C_cand) > blockNo(C_ours) + weightBoost(C_ours)` (heavier by Peras total weight)

…and the tip of `C_cand` is beyond the forecast horizon, `checkPreferTheirsOverOurs` returns `ShouldNotSwitch` (because it ignores the boost) and throws `CandidateTooSparse`, disconnecting from the peer. The node remains on the lighter chain `C_ours`, which is non-canonical under Peras rules.

If all peers serving `C_cand` are disconnected for this reason, the node is permanently stuck on the lighter chain. This constitutes a **chain-selection safety failure**: an honest node accepts and retains a non-canonical, less-secure chain.

This is the direct analog of the LooksRare bug: just as the game's winner was determined by agent index (ignoring the true game state of wounded agents), here the chain "winner" is determined by block count alone (ignoring the true Peras weight state), causing the wrong chain to be retained.

---

### Likelihood Explanation

- Peras is implemented and merged into the production codebase; it is disabled by default today but is intended for mainnet activation.
- The forecast-horizon path (`prj lst = Nothing`) is a normal code path triggered whenever a peer's header is more than one stability window ahead of the intersection point — a routine occurrence during sync.
- A Peras-boosted fork that is shorter by block count but heavier by total weight is an explicitly designed and expected scenario: Peras certificates are intended to make shorter forks win over longer ones to accelerate settlement.
- No adversary is required; the bug fires under honest network conditions whenever Peras is active and a boosted fork is being synced.
- The developers have already flagged this with a `TODO` comment referencing `https://github.com/tweag/cardano-peras/issues/64`, confirming awareness of the incorrect behavior.

---

### Recommendation

Replace `emptyPerasWeightSnapshot` in `checkPreferTheirsOverOurs` with the live `PerasWeightSnapshot` read from the ChainDB (the same snapshot used by `chainSelectionForBlock` and `plausibleCandidateChain`). The function must be given access to the STM action `getPerasWeightSnapshot chainDB` and read it atomically alongside `ourFrag`/`theirFrag`.

Alternatively, as the TODO suggests, remove the check entirely (issue #64), since the Genesis Density Disconnection governor already handles the case of peers serving non-preferred chains.

---

### Proof of Concept

```
Setup (Peras active, boost B large enough that blockNo_cand + B > blockNo_ours):

  Immutable tip I
       |
  ... [block A] ← our chain tip (blockNo = N, weightBoost = 0, totalWeight = N)
       |
  ... [block A] ← fork tip    (blockNo = N-1, weightBoost = B, totalWeight = N-1+B > N)
                               ↑ Peras certificate boosts this block

Trigger:
  1. Peer P serves the fork chain. Its tip is beyond the forecast horizon.
  2. readLedgerStateHelper calls checkPreferTheirsOverOurs.
  3. checkPreferTheirsOverOurs calls preferAnchoredCandidate with emptyPerasWeightSnapshot.
  4. Non-Peras path: compares blockNo(N-1) vs blockNo(N) → ShouldNotSwitch (fork is shorter).
  5. throwSTM CandidateTooSparse → node disconnects from P.
  6. Node stays on chain with totalWeight = N, missing the heavier chain with totalWeight = N-1+B.

Expected (correct) behavior:
  preferAnchoredCandidate with live snapshot → ShouldSwitch (fork is heavier) → node stays
  connected and eventually adopts the Peras-boosted fork.
``` [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1814-1819)
```haskell
        case prj lst of
          Nothing -> do
            checkPreferTheirsOverOurs kis'
            retry
          Just ledgerView ->
            return $ return $ Intersects kis' ledgerView
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1834-1851)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
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
