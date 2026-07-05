### Title
Unconditional `validatePerasCert` Acceptance Bypasses All Peras Certificate Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. The production `processCerts` pipeline invokes this function on every certificate received from an unprivileged peer via the ObjectDiffusion mini-protocol. Because the validator always succeeds, a peer can inject arbitrarily crafted Peras certificates — with any round number and any boosted-block point — directly into the `PerasCertDB` and `ChainDB`, bypassing all certificate authorization.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for accepting inbound certificates. The sole concrete instance in the codebase is the catch-all `StandardHash blk =>` instance:

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

This stub is not confined to tests. The production `processCerts` function — called by both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — passes `validatePerasCert mkPerasParams` as its validator argument:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (PerasCertDB.getCertIds perasCertDB)
      (validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
      (void . join . atomically . PerasCertDB.addCert perasCertDB)
      certs
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert` into errors and successes; because `validatePerasCert` always returns `Right`, the error branch is never taken and every certificate is timestamped and stored:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

The `makePerasCertPoolWriterFromChainDB` variant additionally calls `ChainDB.addPerasCertAsync chainDB`, meaning accepted certificates feed directly into chain selection: [4](#0-3) 

The concrete BLS-based certificate type in `Peras.Cert.V1` carries a round number, a boosted-block hash, a voter bitmap, and an aggregate BLS signature — none of which are checked by the stub: [5](#0-4) 

The `BlockSupportsPeras` class itself correctly declares the interface contract: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with:
- An arbitrary `pcCertRound` (any round number, including future rounds)
- An arbitrary `pcCertBoostedBlock` (any block point, including one on an adversarial fork)
- A garbage or replayed `pcSignature`

Because `validatePerasCert` returns `Right` unconditionally, the certificate passes `processCerts` and is stored. Via `addPerasCertAsync`, it enters chain selection. The Peras boost weight (`vpcCertBoost = perasWeight params`) is assigned to the fake certificate, causing the node to prefer the adversarial boosted block over the honest chain tip. This is a direct bypass of Peras certificate/signature validation enabling unauthorized certificate acceptance — matching the Critical impact category.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is the standard inbound path for Peras objects from any connected peer. No stake, key material, or privileged access is required. Any peer that can establish a connection can send crafted certificates. The stub is the only `BlockSupportsPeras` instance in the repository and is unconditionally used in both `PerasCertDB` and `ChainDB` pool writers. Likelihood is **High** once the Peras protocol is active on a network running this code.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that checks, at minimum:

1. **Aggregate BLS signature** over `(pcRoundNo, pcBoostedBlock)` using the committee's aggregate public key.
2. **Voter eligibility**: each seat index in `pcVoters` must correspond to a committee member elected for `pcRoundNo` via the VRF-based sortition.
3. **Quorum**: the total stake of the verified voters must exceed the configured `perasQuorumStakeThreshold`.
4. **Round bounds**: `pcCertRound` must fall within the currently acceptable window (not arbitrarily far in the future or past).

The `PerasCert.V1` module already defines the wire format with the necessary fields; the validation logic must be wired through `BlockSupportsPeras` before the ObjectDiffusion pipeline is enabled in production.

---

### Proof of Concept

```
1. Attacker connects to a syncing node via the ObjectDiffusion mini-protocol.

2. Attacker sends a batch containing one crafted PerasCert:
     pcCertRound        = <current round + 1>
     pcCertBoostedBlock = <point on attacker's fork>
     pcVoters           = <empty or replayed bitmap>
     pcSignature        = <zeroed aggregate BLS signature>

3. processCerts calls (validatePerasCert mkPerasParams) on the cert.
   validatePerasCert returns:
     Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
   No error is raised.

4. The cert is timestamped and passed to addPerasCertAsync chainDB.

5. Chain selection now treats the attacker's fork as boosted by vpcCertBoost,
   causing the honest node to prefer the adversarial chain over the canonical chain.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```
