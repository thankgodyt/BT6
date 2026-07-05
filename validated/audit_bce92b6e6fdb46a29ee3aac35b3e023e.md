### Title
Peras Certificate Validation Unconditionally Accepts All Peer-Supplied Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This stub is wired directly into the production network-facing inbound certificate pipeline (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can inject arbitrary Peras certificates for any round and any block point; each accepted certificate receives a chain-selection weight boost (`vpcCertBoost`), enabling an adversary to manipulate chain selection without possessing any valid committee keys.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must approve every inbound Peras certificate before it enters the node's certificate database and influences chain selection. The repository ships a single universal instance that covers all block types:

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

This stub is not isolated to tests. It is the function passed directly to `processCerts` in both production pool-writer constructors:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate not already in the database, and only rejects a batch when the validator returns `Left`. Because the stub always returns `Right`, the rejection branch is unreachable:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

Every accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the weight applied to the boosted block during chain selection. The main block-validation path (`updateChainDepState` → `validateKESSignature` / `validateVRFSignature`) enforces full cryptographic checks; the Peras certificate ingest path skips all of them. [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `pcCertBoostedBlock` and any `pcCertRound`. The node will accept it, store it, and apply the Peras weight boost to the named block during chain selection. By injecting certificates that boost a minority or adversarial fork, the attacker can cause an honest node to prefer a non-canonical chain, constituting a chain-selection safety failure. This matches the **Critical** impact category: bypass of Peras certificate checks enabling unauthorized certificate acceptance that materially affects chain selection.

---

### Likelihood Explanation

The attack requires only a network connection to a node that has the Peras object-diffusion mini-protocol enabled. No keys, stake, or operator access are needed. The `makePerasCertPoolWriterFromChainDB` constructor is the production path; the TODO comment confirms the stub is intentionally temporary but is currently live code.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's BLS/committee signature against the current committee public keys.
2. That the boosted block point exists on a known chain and is within the valid round window.
3. That the round number is within the acceptable range relative to the current tip.

Until a real implementation is available, the `opwAddObjects` handler should reject all inbound certificates (return an error or no-op) rather than unconditionally accepting them.

---

### Proof of Concept

1. Connect to a node with the Peras object-diffusion protocol active.
2. Send a `PerasCert` message with `pcCertBoostedBlock` pointing to an adversarial fork tip and an arbitrary `pcCertRound`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. Chain selection now applies `vpcCertBoost` to the adversarial fork, potentially causing the node to switch to it. [1](#0-0) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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
