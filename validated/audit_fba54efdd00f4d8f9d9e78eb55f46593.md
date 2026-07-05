### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peras Certificate, Bypassing All Cryptographic Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that always returns `Right` (success) without performing any actual certificate validation. This is the direct analog of the external report's `sqrtPriceLimitX96: 0` pattern: a hardcoded default value is substituted where a real constraint check must occur. Any unprivileged peer can send a crafted Peras certificate that is unconditionally accepted, stored in `PerasCertDB`, and used to inject an artificial weight boost into chain selection, potentially causing honest nodes to prefer a non-canonical chain.

---

### Finding Description

The production `BlockSupportsPeras` instance — explicitly marked as the universal instance for **all** block types — implements `validatePerasCert` as follows:

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

This function:
1. **Always returns `Right`** regardless of the certificate's content — no signature check, no VRF proof check, no committee membership check, no round-number or target-block check.
2. **Hardcodes the boost** to `perasWeight params` (default `PerasWeight 15` from `mkPerasParams`) — analogous to `sqrtPriceLimitX96: 0`, a fixed value substituted where a computed, validated quantity is required. [2](#0-1) 

The universal instance declaration confirms this applies to every block type, including Cardano blocks:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [3](#0-2) 

The accepted `ValidatedPerasCert` is stored in `PerasCertDB` via `addCert`, which then feeds `getWeightSnapshot`: [4](#0-3) 

The `PerasWeightSnapshot` returned by `getWeightSnapshot` is passed directly into `preferAnchoredCandidate` and `chainSelection` in `ChainSel.hs`, where it determines which chain the node selects: [5](#0-4) [6](#0-5) 

The weight boost is computed as `wsvTotalWeight = blockNo + wsvWeightBoost`, so injecting a `PerasWeight 15` boost onto an attacker-chosen block directly shifts the chain-selection comparison: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` targeting any block hash. Because `validatePerasCert` unconditionally returns `Right`, the certificate is accepted, stored, and its `PerasWeight 15` boost is applied to the targeted block in every subsequent chain-selection comparison. This allows the attacker to:

- Artificially elevate a shorter or weaker fork above the canonical chain by boosting a block on that fork.
- Cause an honest node to switch to a non-canonical chain, constituting a chain-selection safety failure.
- Bypass all Peras certificate checks (aggregate BLS signature, batch VRF verification, committee membership, round validity) that the `WFALS`/`EveryoneVotes` committee implementations are designed to enforce.

This falls under **Critical — Bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation**.

---

### Likelihood Explanation

The entry path requires only a standard peer connection. No stake, no key material, and no operator access are needed. The attacker constructs an arbitrary `PerasCert` record (two fields: `pcCertRound` and `pcCertBoostedBlock`) and submits it via the Peras certificate diffusion mini-protocol. The stub is the only production implementation for all block types; there is no override. Likelihood is **High** whenever the Peras diffusion layer is active.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:

1. Verifies the aggregate BLS vote signature over `(electionId, candidate)` using `verifyAggregateVoteSignature`.
2. Performs batch VRF verification for non-persistent voters via `batchVerifyVRFOutputs`.
3. Checks committee membership and quorum threshold against the current `PerasVoteStakeDistr`.
4. Validates the certificate's round number and target block against the current chain state.

Until a full implementation is available, the function should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), to fail safely.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the Peras certificate diffusion mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on a weaker fork>`.
3. Submit the certificate. The node calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }` unconditionally.
4. The certificate is stored in `PerasCertDB`; `getWeightSnapshot` now returns a snapshot boosting the targeted block by 15.
5. On the next chain-selection event, `preferAnchoredCandidate` computes `wsvTotalWeight` for the boosted fork as `blockNo + 15`, potentially exceeding the canonical chain's weight and causing the node to switch to the attacker-chosen fork. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L174-178)
```haskell
    case NE.nonEmpty
      [ (chain, reason)
      | chain <- chains
      , ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
      ] of
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
