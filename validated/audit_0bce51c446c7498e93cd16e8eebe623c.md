### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Chain Selection Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or semantic checks. Because `ValidatedPerasCert` is the type-level proof that a certificate is legitimate, and because the Peras certificate diffusion path calls this function on every inbound certificate from a peer, any unprivileged peer can inject arbitrary fake Peras certificates. Those certificates are stored in the `PerasCertDB`, their boosted-block points are added to the `PerasWeightSnapshot`, and chain selection is immediately re-run with the inflated weights — potentially causing the node to prefer an adversarial chain over the honest one.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

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

This is the **only** instance of `BlockSupportsPeras` in the codebase — it is a universal instance (`instance StandardHash blk => BlockSupportsPeras blk`) explicitly described as a "degenerate instance for all blks to get things to compile". [2](#0-1) 

**Inbound path — `processCerts` calls the stub:**

Every certificate received from a peer over the Peras object-diffusion mini-protocol is passed through `processCerts`, which calls `validatePerasCert mkPerasParams`. Because the stub always returns `Right`, every certificate passes validation and is timestamped and forwarded to the ChainDB. [3](#0-2) 

**Storage — `implAddCert` stores the certificate:**

`implAddCert` has its own TODO noting missing validation, but even if that were fixed, the certificate has already been "validated" by the stub before reaching this point. [4](#0-3) 

**Weight injection — `implGetWeightSnapshot` feeds the fake boost into chain selection:**

The `PerasWeightSnapshot` is built directly from all stored certificates, including fake ones. [5](#0-4) 

**Chain selection — `weightedSelectView` uses the inflated snapshot:**

`weightedSelectView` computes `wsvWeightBoost = weightBoostOfFragment weights frag`, where `weights` is the `PerasWeightSnapshot` containing the fake boost. `wsvTotalWeight` then adds this boost to the block number, and `preferAnchoredCandidate` uses this total to decide whether to switch chains. [6](#0-5) [7](#0-6) [8](#0-7) 

**Chain selection trigger — `chainSelSync` re-runs selection for the boosted block:**

After a certificate is stored, `chainSelSync` immediately triggers chain selection for the boosted block if it is present in the VolatileDB. [9](#0-8) 

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` message that names any block hash the peer knows is in the target node's VolatileDB (e.g., a block the peer itself served). The fake certificate is accepted without any check, stored, and its weight boost is immediately applied to chain selection. If the boosted block is on an adversarial fork, the adversarial chain's `wsvTotalWeight` is artificially inflated, potentially exceeding the honest chain's weight and causing the node to switch to the adversarial chain. This is a **bypass of Peras certificate verification** that enables unauthorized certificate acceptance and a **chain selection safety failure** — an honest node can be made to prefer a non-canonical chain by a single unprivileged peer.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is a public, unauthenticated network interface. Any peer that can connect to the node can send arbitrary `PerasCert` objects. The only prerequisite is knowing a block hash present in the target's VolatileDB, which is trivially satisfied by any peer that has served at least one block to the target. No stake, no keys, and no special privileges are required.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's BLS/committee signature(s) against the known Peras committee for the relevant round.
2. That the boosted block's slot falls within the valid range for the certificate's round number.
3. That the certificate's quorum threshold is met by the included votes.

Until real validation is in place, inbound certificates from untrusted peers should be rejected entirely (or the Peras weight path should be disabled). The existing TODO at `https://github.com/tweag/cardano-peras/issues/120` tracks this work and should be treated as a security-critical item.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to the victim node as a normal peer.
2. Attacker serves a short adversarial fork (blocks `A1`, `A2`) to the victim; these blocks enter the victim's VolatileDB.
3. Attacker sends a `PerasCert` message over the Peras object-diffusion mini-protocol with `pcCertBoostedBlock = blockPoint A2` and an arbitrary `pcCertRound`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is stored in `PerasCertDB`; `implGetWeightSnapshot` now returns a snapshot that assigns `perasWeight` boost to `A2`.
6. `chainSelSync` calls `chainSelectionForBlock` for `A2`; `preferAnchoredCandidate` computes `wsvTotalWeight` for the adversarial suffix as `blockNo(A2) + perasWeight`, which may exceed the honest chain's weight.
7. The victim node switches to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L104-112)
```haskell
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
