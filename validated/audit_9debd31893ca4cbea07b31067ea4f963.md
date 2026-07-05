### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives. The inbound certificate pipeline (`processCerts`) in `ObjectPool/PerasCert.hs` passes every peer-supplied `PerasCert` through this stub using hardcoded default parameters (`mkPerasParams`) instead of the actual configured protocol parameters. As a result, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block's weight in chain selection, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause 1 — stub validation always returns `Right`:** [1](#0-0) 

The `validatePerasCert` method of the universal `BlockSupportsPeras` instance is explicitly marked as a TODO stub and performs zero cryptographic or structural checks. It wraps the raw, unvalidated `PerasCert` directly into a `ValidatedPerasCert` and assigns it the configured `perasWeight`. No committee membership check, no signature verification, no round-number plausibility check, and no boosted-block existence check is performed.

**Root cause 2 — hardcoded default params used in the production inbound pipeline:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` — the production writer used when Peras is enabled — calls `validatePerasCert mkPerasParams`, where `mkPerasParams` is the hardcoded default bundle rather than the actual per-node configured parameters. This is the analog of the uninitialized `_mesonContract` address: the validation call site uses a default/placeholder value instead of the real configured state.

**Root cause 3 — `processCerts` adds every "validated" cert to the ChainDB:** [3](#0-2) 

Because `validateCert` (bound to `validatePerasCert mkPerasParams`) always returns `Right`, the `([], validatedCerts)` branch is always taken and every inbound certificate is forwarded to `ChainDB.addPerasCertAsync`.

**How the accepted cert affects chain selection:**

The `PerasCertDB` weight snapshot is consumed by `weightedSelectView` to compute `wsvWeightBoost`: [4](#0-3) 

`preferCandidate` then compares `wsvTotalWeight` (= `BlockNo` + `PerasWeight` boost) between the current chain and a candidate: [5](#0-4) 

A crafted certificate with `pcCertBoostedBlock` pointing to any block on a non-canonical fork adds `perasWeight` (default: 15) to that block's effective chain weight, making the node prefer the shorter/non-canonical fork.

---

### Impact Explanation

When Peras is enabled (via `rnFeatureFlags`), an unprivileged peer connected via the Peras certificate diffusion mini-protocol can send a `PerasCert` with an arbitrary `pcCertBoostedBlock`. The cert bypasses all validation, is stored in the `PerasCertDB`, and its boost is applied to chain selection. By sending multiple crafted certificates boosting different blocks on a non-canonical fork, an attacker can accumulate enough artificial weight to make an honest node switch away from the canonical chain. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is active on any node that has Peras enabled in `rnFeatureFlags`. The `makePerasCertPoolWriterFromChainDB` path is the production code path. Any peer that can establish a connection and negotiate the Peras object-diffusion sub-protocol can send arbitrary `PerasCert` objects. No stake, no key material, and no prior knowledge of the chain is required — only the ability to construct a valid CBOR-encoded `PerasCert` (two fields: a `PerasRoundNo` and a `Point blk`). The attack is trivially reproducible on a private testnet with Peras enabled.

---

### Recommendation

1. **Short term**: Replace the stub `validatePerasCert` body with a real implementation that at minimum checks committee membership, the VRF/BLS certificate signature, and that `pcCertBoostedBlock` refers to a known block. Until real validation is in place, gate the inbound certificate pipeline so that no peer-supplied certificate can influence chain selection.

2. **Short term**: Replace the hardcoded `mkPerasParams` in `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` with the actual per-node configured `PerasParams` passed through the `NodeKernelArgs` / `ProtocolInfo` plumbing, mirroring the pattern used for all other consensus configuration.

3. **Long term**: Audit all `-- TODO: perform actual validation` stubs in the `BlockSupportsPeras` instance (`validatePerasCert`, `validatePerasVote`, `forgePerasCert`) and ensure none of them are reachable from the network before real validation logic is in place.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node as an unprivileged peer and negotiate the Peras certificate object-diffusion sub-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the target node's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of a block on a non-canonical fork known to the target node
3. Send the crafted cert via `opwAddObjects`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
5. The cert is forwarded to `ChainDB.addPerasCertAsync`.
6. The `PerasWeightSnapshot` now assigns weight 15 to the non-canonical block.
7. `weightedSelectView` computes `wsvTotalWeight` for the non-canonical fork as `BlockNo + 15`, potentially exceeding the canonical fork's weight.
8. `preferCandidate` returns `ShouldSwitch`, and the node adopts the non-canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L94-112)
```haskell
weightedSelectView ::
  ( GetHeader1 h
  , HasHeader (h blk)
  , HeaderHash blk ~ HeaderHash (h blk)
  , BlockSupportsProtocol blk
  ) =>
  BlockConfig blk ->
  PerasWeightSnapshot blk ->
  AnchoredFragment (h blk) ->
  WithEmptyFragment (WeightedSelectView (BlockProtocol blk))
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
