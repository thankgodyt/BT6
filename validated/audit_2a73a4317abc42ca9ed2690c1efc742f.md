Based on my analysis of the relevant source files, here is my determination:

---

### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peras Certificate, Enabling Unauthorized Chain-Selection Boost — (`Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every input certificate. Any peer reachable via the NodeToNode object-diffusion protocol can therefore inject an arbitrary Peras certificate, which will be stored in the ChainDB and trigger asynchronous chain selection with the full `perasWeight` boost applied to an attacker-chosen block.

### Finding Description

**1. Stub validation always succeeds**

The only `BlockSupportsPeras` instance in the codebase is the degenerate catch-all instance. Its `validatePerasCert` implementation performs no cryptographic, committee-membership, quorum, or round-validity checks: [1](#0-0) 

Every certificate, regardless of content, is wrapped in `Right ValidatedPerasCert` with the full `perasWeight` boost assigned.

**2. Inbound path calls `processCerts` with this stub**

`makePerasCertPoolWriterFromChainDB` wires the stub directly into the inbound object-diffusion writer: [2](#0-1) 

`processCerts` calls `validateCert` on each received certificate; because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is forwarded to `addCert`: [3](#0-2) 

**3. Async promise is dropped; chain-selection side-effect is unobservable by the inbound handler**

The `addCert` callback is `void . ChainDB.addPerasCertAsync chainDB`. The comment acknowledges the promise is intentionally discarded: [4](#0-3) 

Once the cert is handed to the ChainDB background thread, any resulting chain switch is invisible to the inbound diffusion handler. There is no rollback path.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `Point blk` as the boosted block. If a competing fork carrying that block is already present in the VolatileDB (a normal condition during network operation), the ChainDB's chain-selection logic will apply the full `perasWeight` (default: 15 slots) boost to that fork. If the boosted fork then outweighs the current chain, the node switches to the adversarially chosen fork. This constitutes:

- **Bypass of Peras certificate/signature/committee validation** — the stub skips all of it.
- **Unauthorized chain-selection side-effect** — the node can be moved to a fork chosen by the attacker without any honest quorum having certified it.

### Likelihood Explanation

The attack requires only a standard NodeToNode connection and knowledge of a block hash present in the target node's VolatileDB (obtainable via ChainSync). No key material, stake, or operator access is needed. The stub is in the single universal `BlockSupportsPeras` instance used by all block types. [5](#0-4) 

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- Committee membership and VRF eligibility of each signer.
- Aggregate/threshold signature over the certified block point and round number.
- Round number is within the valid window (`perasCertMaxRounds`).
- The certified block point exists on a chain that is a valid extension of the current immutable tip.

Until real validation is in place, the inbound object-diffusion handler for Peras certificates should be disabled or gated behind a feature flag so that no peer-supplied certificate can reach `addPerasCertAsync`.

### Proof of Concept

An io-sim scenario suffices:

1. Set up a ChainDB with two forks: the current chain `C` and a fork `F` that is lighter than `C` by fewer than `perasWeight` slots.
2. Connect a simulated peer via the object-diffusion inbound handler backed by `makePerasCertPoolWriterFromChainDB`.
3. Have the peer send a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = tip(F) }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right` (stub).
5. `ChainDB.addPerasCertAsync` is called; the background thread applies the boost and switches to `F`.
6. Assert `ChainDB.getCurrentChain` now returns `F` — the node is on the adversarially boosted fork despite no honest quorum having certified it.

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
