### Title
Peras Certificate Validation Unconditionally Accepts Any Certificate, Enabling Arbitrary Chain-Selection Weight Injection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero validation. This is the direct analog of the Pareto `requestRedeem` bug: just as `requestRedeem` records a withdrawal amount without checking whether actual collateral backs it, `validatePerasCert` records a certificate as valid without checking whether any actual quorum, cryptographic proof, or round-rule backs it. An unprivileged peer can inject crafted `PerasCert` objects that are accepted without scrutiny, causing the node to apply arbitrary Peras weight boosts to non-canonical chains and thereby corrupting chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:**

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

This is the **universal default instance** for all `StandardHash blk`, meaning it applies to every block type unless explicitly overridden:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

No production override exists. The function signature promises to return `Either (PerasValidationErr blk) (ValidatedPerasCert blk)`, but the implementation discards the `Either` entirely and always produces a `ValidatedPerasCert` carrying the full configured `perasWeight`.

**How the validated certificate reaches chain selection:**

Once a raw `PerasCert` is "validated" (trivially), it becomes a `ValidatedPerasCert` and is passed to `addPerasCertAsync`, which triggers `chainSelSync` → `chainSelectionForBlock`:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
``` [3](#0-2) 

The certificate's boosted block is then looked up in the VolatileDB and chain selection is triggered for it:

```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection reads the live `PerasWeightSnapshot` and uses it in `preferAnchoredCandidate`:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [5](#0-4) 

`weightBoostOfFragment` then sums the boost for every point on the candidate fragment:

```haskell
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap = mempty
  | otherwise =
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
``` [6](#0-5) 

And `preferAnchoredCandidate` uses the inflated weight to decide whether to switch chains:

```haskell
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
``` [7](#0-6) 

**Structural analogy to the Pareto bug:**

| Pareto `requestRedeem` | Ouroboros `validatePerasCert` |
|---|---|
| Stores withdrawal amount without checking actual collateral | Stores certificate as valid without checking quorum/signatures |
| Assumes 1 USP = 1 underlying collateral unconditionally | Assumes every `PerasCert` carries a legitimate boost unconditionally |
| Newer depositors bear losses they did not incur | Nodes switch to chains boosted by certificates that were never earned |
| Bad debt placed on participants who joined after the loss | Non-canonical chain gains weight from certificates with no real backing |

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` pointing to any block in the VolatileDB. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored in `PerasCertDB`, and its full `perasWeight` boost is applied to every chain fragment containing that block. If the boosted block is on a minority fork, the node may now compute that fork as heavier than the honest chain and switch to it — a **chain-selection safety failure** caused by a certificate that was never backed by a real quorum. This matches the allowed impact scope: "Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."

---

### Likelihood Explanation

The attack requires only a network connection to the target node. No stake, no keys, no operator access. The attacker sends a `PerasCert` for any block already in the node's VolatileDB. The code path is unconditional: `validatePerasCert` returns `Right` for every input, so there is no probabilistic or resource barrier.

---

### Recommendation

Replace the stub with real certificate validation before the `ValidatedPerasCert` wrapper is produced. At minimum, `validatePerasCert` must verify:

1. The certificate's round number is within the current Peras epoch window.
2. The boosted block point is a known, valid block on a plausible chain.
3. The certificate carries a valid aggregate signature from a quorum of eligible committee members.
4. The certificate has not already been superseded by a later certificate for the same round.

Until a real implementation is available, the function should return `Left PerasValidationErr` by default (fail-closed) rather than `Right` (fail-open), so that no certificate is accepted unless explicitly validated.

---

### Proof of Concept

```
1. Attacker connects to an honest node as a peer.
2. Attacker observes that block B (on a minority fork) is in the node's VolatileDB.
3. Attacker constructs PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = blockPoint B }.
4. Attacker sends the certificate via the Peras certificate diffusion mini-protocol.
5. Node calls validatePerasCert params cert  →  Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }).
6. Node calls addPerasCertAsync with the ValidatedPerasCert.
7. chainSelSync triggers chainSelectionForBlock for B.
8. getPerasWeightSnapshot now includes B with full perasWeight boost.
9. preferAnchoredCandidate computes the minority fork as heavier than the honest chain.
10. Node switches to the minority fork — chain-selection safety failure.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-495)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L259-267)
```haskell
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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
