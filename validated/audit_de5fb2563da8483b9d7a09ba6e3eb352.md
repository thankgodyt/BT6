### Title
`validatePerasCert` Unconditionally Accepts All Peras Certificates Without Cryptographic or Quorum Validation, Enabling Fake-Certificate Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound Peras certificate without verifying the aggregate BLS signature, committee membership, or quorum threshold. Because this function is wired directly into the peer-facing certificate ingestion pipeline (`processCerts`), any unprivileged peer can inject an arbitrarily crafted certificate that will be stored in the `PerasCertDB` and used to boost a chosen block's weight in chain selection.

---

### Finding Description

**Root cause — missing validation in `validatePerasCert`:**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for all inbound certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance (the only production instance, explicitly marked "TODO: degenerate instance for all blks to get things to compile") implements it as:

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

No signature is verified. No committee membership is checked. No quorum threshold is enforced. Every certificate, regardless of content, is stamped `ValidatedPerasCert` and assigned the full Peras boost weight. [1](#0-0) 

**Call path from peer input to chain selection:**

`processCerts` in `PerasCert.hs` is the inbound handler for certificates received from remote peers via the ObjectDiffusion mini-protocol. It calls the injected `validateCert` function on each certificate not already in the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both production pool writers pass `validatePerasCert mkPerasParams` as the `validateCert` argument:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate sent by a peer passes the `partitionEithers` check and is unconditionally added to the `PerasCertDB` with `vpcCertBoost = perasWeight params`.

**What the missing checks are:**

The concrete Peras certificate type (`Peras.Cert.V1.PerasCert`) carries an aggregate BLS signature (`pcSignature`), a voter bitmap (`pcVoters`), and a boosted block hash (`pcBoostedBlock`). A correct `validatePerasCert` must verify:
1. The aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)`.
2. That each voter seat index in `pcVoters` corresponds to a legitimate committee member.
3. That the total voting weight of the voters meets the quorum threshold. [4](#0-3) 

None of these checks are performed. The `PerasValidationErr` data constructor is a single opaque `PerasValidationErr` with no variants, confirming no error path is reachable. [5](#0-4) 

---

### Impact Explanation

A `ValidatedPerasCert` stored in the `PerasCertDB` carries `vpcCertBoost = perasWeight params`. This boost weight is applied to the certified block during chain selection: the Peras protocol is designed so that a certified block's chain is preferred over an uncertified chain of equal or slightly greater length. An attacker who can inject a fake certificate pointing to an arbitrary block hash can therefore cause an honest node to prefer a non-canonical chain — a chain-selection manipulation that violates the safety guarantees of the Peras extension.

**Impact category:** High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The entry path requires only that the attacker be a connected peer participating in the ObjectDiffusion mini-protocol for Peras certificates. No privileged keys, no stake, no prior authentication is required. The attacker constructs a `PerasCert` with an arbitrary `pcBoostedBlock` pointing to a block on a minority or adversarial fork, serializes it as valid CBOR, and sends it. The receiving node's `processCerts` pipeline will accept it unconditionally.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature in `pcSignature` over `(pcRoundNo, pcBoostedBlock)` using the public keys of the voters identified in `pcVoters`.
2. Checks each voter seat index against the current committee membership (persistent or non-persistent via VRF eligibility proof).
3. Confirms the total voting weight of the voters meets the quorum threshold defined in `PerasCfg`.

Until the concrete Cardano Peras integration is complete, the stub should at minimum reject all certificates (return `Left PerasValidationErr`) rather than accept all of them, so that the degenerate instance is safe-by-default.

---

### Proof of Concept

1. Attacker connects to a target node as a peer via the ObjectDiffusion mini-protocol for Peras certificates.
2. Attacker constructs a `PerasCert` with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <hash of a block on an adversarial fork>`
   - `pcVoters = <any bitmap, e.g., all zeros>`
   - `pcSignature = <any bytes, e.g., all zeros>`
3. Attacker sends the certificate to the target node.
4. `makePerasCertPoolWriterFromChainDB` calls `processCerts` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
5. The certificate is stored in `PerasCertDB` with full boost weight.
6. Chain selection now treats the adversarial fork's block as boosted, preferring it over the honest chain of equal or slightly greater length. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-60)
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
```
