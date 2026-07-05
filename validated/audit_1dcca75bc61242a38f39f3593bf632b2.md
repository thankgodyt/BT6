### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` claiming an arbitrary block won a Peras round, and the node will accept it, apply the Peras weight boost to the attacker-chosen block, and trigger chain selection — potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve every inbound Peras certificate before it enters the database and influences chain selection. The only concrete instance in the codebase — the one used in all production paths — is:

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

This stub is the **only** instance, declared as a "degenerate instance for all blks": [2](#0-1) 

This validator is wired directly into both production inbound-certificate processing paths:

**Path 1 — `PerasCertDB` writer:**
```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

**Path 2 — `ChainDB` writer (production path):**
```haskell
(validatePerasCert mkPerasParams)
``` [4](#0-3) 

The `processCerts` function that calls this validator accepts the entire batch if all certs pass validation. Since `validatePerasCert` always returns `Right`, every cert from every peer passes: [5](#0-4) 

The accepted cert is then added via `addPerasCertAsync`, which triggers chain selection: [6](#0-5) 

A `PerasCert` contains only a round number and a boosted block point — both fully attacker-controlled: [7](#0-6) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An attacker who sends a crafted `PerasCert` claiming that an arbitrary block `B` won Peras round `R` will have that certificate accepted unconditionally. The certificate is stored in the `PerasCertDB` and its `vpcCertBoost` weight is applied to block `B` during chain selection. If `B` is on a minority or adversarial fork, the Peras weight boost can make that fork appear heavier than the honest chain, causing the node to switch to the attacker's preferred chain. This is a direct chain-selection safety failure triggered by a single network message from an unprivileged peer.

---

### Likelihood Explanation

**Likelihood: High.** The attacker-controlled entry path is the standard Peras certificate object-diffusion mini-protocol, reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The `PerasCert` wire format is simple (round number + block point), trivially constructable. The bypass requires sending exactly one message.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that:
1. Verifies the certificate's aggregate signature against the claimed committee members.
2. Checks that the claimed voters collectively hold stake above the quorum threshold.
3. Verifies each voter's eligibility proof (VRF output or persistent membership) against the stake distribution for the relevant epoch.

Until the full committee selection plumbing (tracked in issue #73 and #120) is in place, the stub should at minimum reject all inbound certificates from peers rather than accepting them unconditionally, to prevent the bypass from being exploitable in any deployed testnet or pre-production environment.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras cert object-diffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound = <any round number not yet in the DB>`
   - `pcCertBoostedBlock = <point of an attacker-chosen block on a minority fork>`
3. Send the cert in a batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The cert is added to the `PerasCertDB` and `addPerasCertAsync` is called, triggering chain selection.
6. The Peras weight boost is applied to the attacker-chosen block, potentially causing the node to switch to the attacker's fork. [1](#0-0) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
