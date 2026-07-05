### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation for all block types unconditionally returns `Right` (success) without performing any cryptographic or structural verification of the certificate. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` value; the certificate passes validation, is stored in the `PerasCertDB`, and triggers chain selection with an attacker-controlled weight boost, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must be passed before a certificate received from the network is stored and acted upon. The universal instance — the only instance in the codebase — is:

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

This stub ignores every field of `cert` and always returns `Right`. The `vpcCertBoost` is taken from the local `params` rather than from any proof carried by the certificate, so the boost value is always the configured `perasWeight` regardless of what the certificate claims.

The network-facing inbound path calls this function directly:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- ← always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
```

`processCerts` partitions results into valid/invalid; because `validatePerasCert` never produces a `Left`, every certificate in every inbound batch is classified as valid and forwarded to `addPerasCertAsync`. That function enqueues a `ChainSelAddPerasCert` message, which:

1. Adds the certificate to `PerasCertDB`.
2. Looks up the `pcCertBoostedBlock` in the `VolatileDB`.
3. If found, calls `chainSelectionForBlock` for that block, giving it the configured weight boost.

An attacker therefore controls `pcCertBoostedBlock` — the block whose chain selection weight is inflated — with no cryptographic barrier.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

By sending a `PerasCert` whose `pcCertBoostedBlock` points to a block on an adversarial fork that is already in the victim's `VolatileDB`, the attacker causes `chainSelectionForBlock` to re-evaluate that fork with an additional `perasWeight` boost. If the boosted fork's `wsvTotalWeight` then exceeds the current chain's `wsvTotalWeight`, the node switches to the adversarial fork. This directly undermines the Peras chain-selection invariant that only legitimately certified blocks should receive a weight boost.

---

### Likelihood Explanation

Any peer connected via the Peras certificate diffusion mini-protocol can trigger this. No key material, stake, or special privilege is required — only the ability to send a well-formed CBOR-encoded `PerasCert` message. The `PerasCert` type is serialisable and its fields (`pcCertRound`, `pcCertBoostedBlock`) are fully attacker-controlled. The attack is repeatable and requires no brute force.

---

### Recommendation

Replace the stub with a real implementation that verifies the aggregate BLS signature and VRF outputs carried by the certificate against the voting committee derived from the ledger state at the relevant epoch, as specified by the `verifyCert` interface in `Committee.Class` and implemented for `WFALS`/`EveryoneVotes`. Until that plumbing is complete, the inbound certificate path should reject all certificates rather than accept them unconditionally, to avoid the current bypass.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects and runs the Peras certificate diffusion protocol (`hPerasCertDiffusionClient`).
2. Peer sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialPoint }` where `adversarialPoint` is the `Point` of a block already present in the victim's `VolatileDB`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }`.
4. `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
5. `chainSelSync` finds `adversarialPoint` in `VolatileDB`, calls `chainSelectionForBlock` with the boosted weight.
6. `preferAnchoredCandidate` compares `wsvTotalWeight` including the boost; if the adversarial fork is now heavier, the node switches.

**Root cause lines:** [1](#0-0) 

**Network inbound path that calls the stub:** [2](#0-1) 

**`processCerts` that forwards all "valid" certs to ChainDB:** [3](#0-2) 

**Chain selection triggered for the boosted block:** [4](#0-3) 

**Weight boost used in chain comparison:** [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
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
