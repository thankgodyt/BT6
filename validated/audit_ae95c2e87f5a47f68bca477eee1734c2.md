### Title
`validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates Without Cryptographic Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — it never rejects any certificate regardless of its content. Because this function is the sole validation gate called by `processCerts` on every certificate received from an unprivileged peer over the object-diffusion mini-protocol, any peer can inject arbitrary Peras certificates that will be accepted, stored, and used to boost arbitrary blocks in chain selection without any cryptographic or semantic check.

---

### Finding Description

**Root cause.** The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the method responsible for validating inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal production instance — explicitly marked `-- TODO: degenerate instance for all blks to get things to compile` — implements this method as:

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

No signature is verified, no round number is checked, no boosted-block validity is confirmed. Every certificate, regardless of content, is wrapped in `Right ValidatedPerasCert` and returned as valid.

**Attacker-controlled entry path.** The object-diffusion mini-protocol receives batches of `PerasCert blk` from remote peers. Both production pool writers — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` calls `validateCert` on each new certificate and, if all pass, adds them to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate sent by any peer is accepted and stored.

**Accepted certificates influence chain selection.** Certificates stored via `ChainDB.addPerasCertAsync` carry a `vpcCertBoost = perasWeight params` field that is used to boost the weight of the certified block during chain selection. A forged certificate pointing at an attacker-chosen block will cause honest nodes to prefer that block. [5](#0-4) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate verification enabling unauthorized certificate acceptance.**

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`, send it over the object-diffusion mini-protocol, and have it accepted and stored without any cryptographic check. The accepted certificate carries a chain-selection boost (`perasWeight`) that causes honest nodes to prefer the attacker-designated block. This directly violates the Peras finality guarantee: the protocol's security property is that only a certificate backed by a quorum of legitimate committee signatures can boost a block, but here any peer can forge that effect with zero credentials.

---

### Likelihood Explanation

**High.** The entry point is the public object-diffusion mini-protocol, reachable by any peer that can establish a connection. No keys, stake, or operator access are required. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase (it is a universal `instance StandardHash blk =>`), so every block type is affected. The TODO comment and linked issue confirm the missing validation is a known gap, not an intentional design choice.

---

### Recommendation

Implement actual cryptographic and semantic validation inside `validatePerasCert` before the instance is used in any production context. At minimum, the implementation must:

1. Verify the aggregate BLS signature in `pcSignature` against the aggregated public keys of the claimed voters.
2. Verify that each claimed voter is a legitimate committee member for the given round (VRF eligibility proof for non-persistent members).
3. Verify that the total stake of the voters meets the quorum threshold.
4. Verify that `pcBoostedBlock` refers to a known, valid block.

Until this is done, the `processCerts` pipeline must not be wired to any live peer connection. The existing `-- TODO: degenerate instance for all blks to get things to compile` comment at line 318 should be treated as a hard blocker for production deployment. [6](#0-5) 

---

### Proof of Concept

1. Connect to a node as an unprivileged peer via the object-diffusion mini-protocol.
2. Send a `PerasCert` message with `pcCertRound = r` (any round) and `pcCertBoostedBlock = B` (any block hash the attacker wishes to boost), with a zeroed or random `pcSignature`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
4. The certificate is stored in the `PerasCertDB` / `ChainDB` with the full Peras boost weight.
5. Chain selection now treats block `B` as having been certified by a quorum, preferring it over competing chains — without any legitimate committee having voted for it.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L100-105)
```haskell
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
