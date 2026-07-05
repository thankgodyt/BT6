### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Arbitrary Chain-Selection Weight Injection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, regardless of its content. Any unprivileged peer can therefore send a crafted `PerasCert` that claims to boost an arbitrary block's weight. Because the Peras weight snapshot is fed directly into `preferAnchoredCandidate`, the injected boost can make an adversarial fork appear heavier than the honest chain, causing the node to switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type-class instance for all blocks contains a stub `validatePerasCert` that performs **no cryptographic or structural checks** and always succeeds:

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

The production inbound-certificate pipeline in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then calls this validator on every inbound certificate and, because all pass, forwards them to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for chain selection processing: [4](#0-3) 

The accepted certificate is stored in the `PerasCertDB`, whose `getWeightSnapshot` is read during every chain-selection invocation. `preferAnchoredCandidate` uses the resulting `PerasWeightSnapshot` to compare candidate fragments:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights = ...   -- normal Praos path
  | otherwise =
      case AF.intersect ours cand of
        Just (_,_,oursSuffix, candSuffix) ->
          case preferCandidate cfg
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of ...
``` [5](#0-4) 

`weightedSelectView` computes `wsvTotalWeight = blockNo + weightBoost`, where `weightBoost` is the sum of all Peras boosts for blocks on the fragment: [6](#0-5) 

A crafted certificate that names a block on an adversarial fork as `pcCertBoostedBlock` will add `perasWeight params` to that fork's total weight, potentially making it exceed the honest chain's weight and triggering a chain switch.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker sends a single `PerasCert` message (via the Peras object-diffusion mini-protocol) naming any block on a shorter adversarial fork as the boosted block. Because `validatePerasCert` always returns `Right`, the certificate is accepted and its boost (`perasWeight`) is added to the adversarial fork's total weight. If `perasWeight > (honest_chain_length − adversarial_fork_length)`, `preferAnchoredCandidate` will return `ShouldSwitch` for the adversarial fork, and the node will roll back to it. This constitutes a consensus safety failure: the node permanently adopts an invalid or non-canonical chain without any stake-majority requirement.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol for Peras certificates is reachable from any connected peer. No special privileges, keys, or stake are required. The attacker only needs to craft a `PerasCert` CBOR message with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The stub is in the default instance used for all block types, so every node running Peras-enabled code is affected. The only mitigating factor is that Peras is not yet activated on mainnet, but the code is present in the production source tree and will be exercised on any private testnet or pre-production environment.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras object-diffusion protocol is enabled. At minimum, verify the BLS aggregate signature over the committee votes, the round number, and the boosted block's presence in the node's known chain.
2. Until real validation is in place, **disable the inbound certificate pipeline** (or gate it behind a feature flag) so that `makePerasCertPoolWriterFromChainDB` is not wired up in production builds.
3. Add a property-based test asserting that `validatePerasCert` rejects certificates with invalid signatures or out-of-range round numbers.

---

### Proof of Concept

**Setup:** A private two-node testnet with Peras object diffusion enabled. Node A is the honest node; Node B is the attacker.

1. Node B observes that Node A's current chain tip is at block `H` (block number 100).
2. Node B has a fork `F` branching at block 90, currently at block number 95 (5 blocks shorter than the honest chain). Assume `perasWeight = 10`.
3. Node B crafts a `PerasCert`:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <point of block 95 on fork F> }
   ```
4. Node B sends this certificate to Node A via the Peras object-diffusion mini-protocol.
5. Node A's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = 10 })`.
6. The certificate is added to Node A's `PerasCertDB`; `getWeightSnapshot` now returns a snapshot with `+10` weight for block 95 on fork F.
7. Chain selection runs: honest chain total weight = 100; fork F total weight = 95 + 10 = 105. `preferAnchoredCandidate` returns `ShouldSwitch`.
8. Node A rolls back 10 blocks and adopts fork F — a non-canonical chain — without any cryptographic proof of quorum. [1](#0-0) [7](#0-6) [6](#0-5) [8](#0-7)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
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
```
