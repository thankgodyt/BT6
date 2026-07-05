### Title
`validatePerasCert` stub unconditionally accepts all inbound Peras certificates without any validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole `BlockSupportsPeras` instance in the codebase provides a degenerate `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or semantic checks. This stub is wired directly into the production Peras certificate inbound-processing pipeline (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can therefore send arbitrarily crafted Peras certificates for any block, and the node will accept and store them as valid, triggering chain-selection boosts for attacker-chosen blocks.

---

### Finding Description

**Root cause — stub validation always succeeds:**

The universal `BlockSupportsPeras` instance (the only instance in the repository) implements `validatePerasCert` as an unconditional success:

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

No signature is verified, no quorum is checked, no round-number bounds are enforced, and no block-hash authenticity is confirmed. The function signature promises `Either (PerasValidationErr blk) (ValidatedPerasCert blk)` but the `Left` branch is structurally unreachable.

**Production wiring — stub is the live validator:**

`makePerasCertPoolWriterFromChainDB` (a production function, not a test helper) passes this stub directly as the certificate validator for all inbound peer certificates:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then treats every certificate that passes this validator as legitimate and forwards it to `ChainDB.addPerasCertAsync`, which triggers chain-selection side-effects: [3](#0-2) 

**Analog to the external report:**

The external report describes a missing `afterSwapReturnDelta` permission flag that causes a return delta to be silently ignored (defaulting to 0), so the intended fee is never applied. Here, the missing validation logic causes the certificate check to be silently bypassed (always returning `Right`), so any certificate is unconditionally accepted. In both cases, a required guard is absent from a configuration/implementation, and the system proceeds as if the guard passed.

---

### Impact Explanation

**Critical — bypass of Peras certificate validation enabling unauthorized chain-selection manipulation.**

A `ValidatedPerasCert` carries a `vpcCertBoost` weight (set to `perasWeight params`) that is applied during chain selection to boost the certified block. Because `validatePerasCert` never rejects any certificate, an attacker can:

1. Craft a `PerasCert` pointing to any block hash and any round number.
2. Send it to a target node via the Peras object-diffusion mini-protocol (no credentials required — any connected peer can submit certificates).
3. The node stores the certificate as `ValidatedPerasCert` and asynchronously triggers chain selection with the attacker-chosen boost.

This allows an unprivileged peer to make an honest node prefer a non-canonical or adversarially chosen chain, violating the Peras chain-selection security assumption. It also constitutes a complete bypass of the Peras certificate-quorum check: the entire purpose of certificate validation is to confirm that a supermajority of committee members voted for the certified block; that check is entirely absent.

---

### Likelihood Explanation

**High.** The attack requires only a standard peer connection — no stake, no keys, no operator access. The Peras object-diffusion mini-protocol is active in the production node build. The attacker needs only to know the wire format of a `PerasCert` (which is CBOR-serialised with a public schema) and a target block hash to boost. The TODO comments confirm the stub is intentional scaffolding that was never replaced with real validation before the mini-protocol was wired up.

---

### Recommendation

Replace the stub `validatePerasCert` in the `BlockSupportsPeras` instance with a real implementation that verifies:

1. The certificate's cryptographic aggregate signature over the round number and block hash.
2. That the signing committee members collectively hold stake above the Peras quorum threshold.
3. That the round number is within the valid window relative to the current tip.

Until real validation is implemented, the Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB` / `makePerasCertPoolWriterFromCertDB`) should refuse all inbound certificates rather than accept them unconditionally. The analogous fix in the external report was adding the missing `afterSwapReturnDelta = true` permission; here the fix is adding the missing validation body rather than leaving it as an unconditional `Right`. [4](#0-3) 

---

### Proof of Concept

```
-- Attacker-controlled peer sends a crafted PerasCert:
--   pcCertRound    = any round number (e.g. the current round)
--   pcCertBoostedBlock = hash of an adversarially chosen block
--
-- processCerts calls:
--   validatePerasCert mkPerasParams craftedCert
--   => Right (ValidatedPerasCert { vpcCert = craftedCert
--                                , vpcCertBoost = perasWeight mkPerasParams })
--   -- no error branch is reachable
--
-- The cert is forwarded to ChainDB.addPerasCertAsync, which triggers
-- chain selection boosting the attacker-chosen block by perasWeight.
--
-- Concrete entry path:
--   peer TCP connection
--     -> Peras object-diffusion mini-protocol handler
--     -> makePerasCertPoolWriterFromChainDB.opwAddObjects [craftedCert]
--     -> processCerts ... (validatePerasCert mkPerasParams) ...
--     -> validatePerasCert always returns Right
--     -> ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
--     -> chain selection runs with boosted adversarial block
``` [5](#0-4)

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
