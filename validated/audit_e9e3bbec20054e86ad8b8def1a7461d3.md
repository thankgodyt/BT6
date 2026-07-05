### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. This stub is wired directly into the production inbound-certificate processing path (`processCerts` → `makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` and have it accepted, stored, and applied as a chain-weight boost, enabling unauthorized manipulation of chain selection.

### Finding Description

The `BlockSupportsPeras` instance (the degenerate catch-all instance used for all block types) implements `validatePerasCert` as a pure stub:

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

No field of `cert` is inspected. No quorum check, no aggregate-signature verification, no round-number bounds check, no boosted-block existence check — the function unconditionally wraps any input in `Right ValidatedPerasCert`.

This stub is the function passed as the `validateCert` argument in both production pool-writer constructors:

- `makePerasCertPoolWriterFromCertDB` (line 103): `(validatePerasCert mkPerasParams)`
- `makePerasCertPoolWriterFromChainDB` (line 126): `(validatePerasCert mkPerasParams)`

Both call `processCerts`, which is the inbound-certificate handler for the ObjectDiffusion mini-protocol. `processCerts` applies `validateCert` to every new certificate received from a remote peer and, if all pass, stores them via `addCert` (either `PerasCertDB.addCert` or `ChainDB.addPerasCertAsync`). Because `validatePerasCert` never returns `Left`, every certificate from every peer passes.

The stored `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params = PerasWeight 15`. The `PerasCertDB` weight snapshot is consumed by chain selection to apply the Peras weight boost to the `pcCertBoostedBlock` named in the certificate. An attacker therefore controls which block receives a `+15` weight boost simply by naming it in a crafted certificate.

The analog to the external report is exact: just as `_transferViaOFT` validated only the received amount and not the sent amount, `validatePerasCert` validates the output wrapper (`ValidatedPerasCert`) but none of the certificate's actual content — the quorum proof, the aggregate signature, the round number, or the boosted block's existence.

### Impact Explanation

**High — chain-selection manipulation by an unprivileged peer.**

Peras certificates exist to boost the chain-selection weight of specific blocks. A `ValidatedPerasCert` with `vpcCertBoost = 15` causes the chain-selection logic to add 15 to the weight of `pcCertBoostedBlock`. An attacker who can inject arbitrary certificates can:

1. Boost an adversarial or minority-fork block, causing honest nodes to prefer it over the canonical chain.
2. Inject a certificate pointing to a block that does not exist or is on a different fork, corrupting the weight snapshot used by chain selection.
3. Inject certificates for future rounds, pre-loading the `PerasCertDB` with fraudulent boosts before those rounds are reached.

This directly satisfies the "High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions" impact category.

### Likelihood Explanation

**High.** The attack requires only a network connection to a node running the Peras ObjectDiffusion mini-protocol. No keys, no stake, no privileged access are needed. The attacker sends a well-formed CBOR-encoded `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The `processCerts` handler accepts it unconditionally. The attack is deterministic and reproducible on any private testnet running this code.

### Recommendation

Replace the stub with a real implementation that, at minimum:

1. Verifies the aggregate vote signature over `(electionId, candidate)` using the committee's aggregate verification key.
2. Checks that the number of voters in the certificate meets the quorum threshold.
3. Validates that `pcCertRound` is within the acceptable window (not expired, not from the future beyond the forecast horizon).
4. Verifies that `pcCertBoostedBlock` refers to a block that is known to the local chain or is plausibly on a valid fork.

Until the full implementation is ready, the stub should at minimum reject all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them, so that the attack surface is closed while development continues.

### Proof of Concept

**Entry path:**

1. Attacker connects to a node and establishes an ObjectDiffusion session for Peras certificates.
2. Attacker sends a batch containing one crafted `PerasCert`:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversarial block point> }
   ```
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` is invoked with `validatePerasCert mkPerasParams` as the validator.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = crafted_cert, vpcCertBoost = 15 }` without inspecting any field.
5. `processCerts` sees zero errors and calls `ChainDB.addPerasCertAsync` with the crafted certificate.
6. The `PerasCertDB` weight snapshot now includes a `+15` boost for the attacker-chosen block.
7. Chain selection applies this boost, potentially preferring the adversarial block over the honest tip.

**Root cause lines:** [1](#0-0) 

**Production call sites that wire the stub into the inbound path:** [2](#0-1) [3](#0-2) 

**`processCerts` — the inbound handler that relies on the validator:** [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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
