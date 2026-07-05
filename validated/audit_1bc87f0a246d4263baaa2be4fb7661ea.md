### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Crafted Certificate, Enabling Unauthorized Chain-Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, assigning the full `perasWeight` boost without performing any cryptographic or quorum verification. An unprivileged peer can craft an arbitrary `PerasCert` for any block point and inject it via the `PerasCertDiffusion` mini-protocol. The certificate is stored and its weight boost is applied to chain selection, allowing the adversary to make honest nodes prefer a non-canonical chain.

### Finding Description

The `BlockSupportsPeras` instance defined for all `StandardHash blk` in `SupportsPeras.hs` contains a stub `validatePerasCert` that performs no validation whatsoever:

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

This stub is the **production code path** used by both cert-pool writers. In `PerasCert.hs`, `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` both call `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` calls `validateCert` on each inbound cert and, if all pass (which they always do), stores them via `addCert`: [4](#0-3) 

The stored `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`. This boost is consumed by `weightBoostOfFragment`, which sums the boost of every point on a fragment: [5](#0-4) 

`wsvTotalWeight` then adds this boost to the block number to produce the total chain weight used in `preferCandidate`: [6](#0-5) [7](#0-6) 

The inbound cert diffusion handler in `NodeToNode.hs` wires this directly to the production `ChainDB`: [8](#0-7) 

**Analog to the external report:** In the Kairos bug, the minimum interest was distributed *equally* per provision regardless of contribution size, allowing an attacker to inflate the provision count and dilute legitimate lenders. Here, the full `perasWeight` boost is assigned *equally* to every certificate regardless of whether it carries legitimate quorum-backed votes, allowing an attacker to inject fake certificates and inflate the weight of any block they choose — diluting the honest chain's weight advantage.

### Impact Explanation

An adversary who can connect as an unprivileged peer can craft a `PerasCert` pointing to any block on their fork and broadcast it. The cert is accepted without signature, quorum, or committee-membership checks. The boosted block gains `perasWeight` additional weight in chain selection. If the adversary's fork is otherwise close in length to the honest chain, the injected boost can tip `preferCandidate` to select the adversary's chain, causing honest nodes to permanently adopt a non-canonical chain. This is a **Critical** bypass of certificate verification enabling unauthorized chain-weight manipulation and potential consensus safety failure.

### Likelihood Explanation

The attack requires only a network connection to a target node — no stake, no keys, no operator access. The `PerasCertDiffusion` mini-protocol is exposed to all node-to-node peers. The stub is the only production implementation (the `instance StandardHash blk => BlockSupportsPeras blk` is the universal fallback). Likelihood is **High** for any deployment that activates the Peras cert diffusion handler.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS/committee signature on the certificate.
2. Confirms the certificate references a known block point.
3. Confirms the quorum threshold was met by the votes backing the certificate.
4. Rejects any certificate that fails these checks before storing it or applying its weight boost.

Until real validation is in place, the `PerasCertDiffusion` inbound handler should not be wired to the production `ChainDB`.

### Proof of Concept

1. Adversary connects to an honest node via the node-to-node protocol.
2. Adversary constructs `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversaryBlockPoint }` for any block point on their fork.
3. Adversary sends the cert via the `PerasCertDiffusion` mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always returns `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })`.
5. The cert is stored in `PerasCertDB` / `ChainDB`.
6. `implGetWeightSnapshot` builds a `PerasWeightSnapshot` that maps `adversaryBlockPoint` to `perasWeight`.
7. `weightBoostOfFragment` adds `perasWeight` to any fragment containing `adversaryBlockPoint`.
8. `wsvTotalWeight` returns `blockNo + perasWeight` for the adversary's fragment.
9. `preferCandidate` selects the adversary's chain if its boosted total weight exceeds the honest chain's weight.
10. The honest node permanently adopts the adversary's non-canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
```
