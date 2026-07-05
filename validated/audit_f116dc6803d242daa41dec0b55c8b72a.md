### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or semantic checks. Any unprivileged peer can inject arbitrary Peras certificates via the ObjectDiffusion mini-protocol. Those certificates are accepted, stored, and used to influence chain selection through the Peras boosting mechanism — without any signature, quorum, or eligibility verification.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a `PerasCert` before it is admitted to the node's cert database or ChainDB. The sole production instance of this class (the catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements the function as:

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

The function ignores every field of the certificate — the BLS aggregate signature (`pcSignature`), the voter bitmap (`pcVoters`), the boosted block hash (`pcBoostedBlock`), and the round number (`pcCertRound`) — and returns `Right` unconditionally.

This function is not dead code. It is wired directly into the two production ObjectDiffusion pool writers that process inbound certificates from remote peers:

```haskell
makePerasCertPoolWriterFromCertDB ... =
  ObjectPoolWriter { opwAddObjects = \certs ->
      processCerts systemTime ... (validatePerasCert mkPerasParams) ... certs }

makePerasCertPoolWriterFromChainDB ... =
  ObjectPoolWriter { opwAddObjects = \certs ->
      processCerts systemTime ... (validatePerasCert mkPerasParams) ... certs }
``` [2](#0-1) 

`processCerts` calls the supplied validation function on every inbound certificate and, if it returns `Right`, timestamps it and stores it in the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate a peer sends passes "validation."

The same structural gap exists for `validatePerasVote`: the degenerate `PerasVote` data type carries no signature field at all, so even the stake-distribution membership check that exists cannot substitute for cryptographic vote authentication. [4](#0-3) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance.**

A Peras certificate, once accepted, is used by chain selection to apply a `PerasWeight` boost to the certified block. An attacker who can inject a fake certificate for an arbitrary `(round, block)` pair can:

1. Boost a block of their choosing, causing honest nodes to prefer a chain they would otherwise not select.
2. Suppress legitimate certificates by filling the per-round slot in the cert DB with a fake cert for the same round number (since the DB deduplicates by round).
3. Trigger chain reorganisations on nodes that have adopted the Peras boosting logic.

The `ValidatedPerasCert` wrapper is the type-level proof that a certificate has been checked. Because `validatePerasCert` produces this proof unconditionally, the type system's safety guarantee is hollow.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is wired into the production `NodeKernel` path. Any peer that speaks the Peras object-diffusion sub-protocol can send a batch of `PerasCert` objects. No stake, no key material, and no prior relationship with the node is required. The attack requires only the ability to open a standard node-to-node connection and send a well-formed (but semantically invalid) CBOR-encoded certificate.

The Peras extension is under active development and the degenerate instance is explicitly labeled a temporary scaffold (`-- TODO: degenerate instance for all blks to get things to compile`), but the production pool-writer code that calls it is not guarded by any feature flag visible in the codebase. [5](#0-4) 

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify the BLS aggregate signature over `(pcRoundNo, pcBoostedBlock)`, check that every voter seat index in `pcVoters` corresponds to an eligible committee member, and confirm that the aggregate signature covers exactly the claimed voter set.

2. **Add a signature field to the degenerate `PerasVote`**: the stub `PerasVote` type omits a signature entirely, making it impossible to authenticate votes even if `validatePerasVote` were strengthened.

3. **Guard the ObjectDiffusion pool writers behind a Peras feature flag** until full validation is in place, so that nodes not participating in Peras do not process inbound cert/vote batches at all.

4. **Add a property-based test** asserting that `validatePerasCert` rejects certificates with invalid signatures, wrong voter bitmaps, or out-of-range round numbers.

---

### Proof of Concept

On a private testnet with Peras ObjectDiffusion enabled:

```
1. Attacker node connects to victim node via standard NtN handshake.
2. Attacker sends an ObjectDiffusion message containing a PerasCert:
     PerasCert { pcRoundNo    = <any round>
               , pcBoostedBlock = <hash of attacker-chosen block>
               , pcVoters     = <empty or arbitrary bitmap>
               , pcSignature  = <zeroed-out BLS signature> }
3. processCerts calls validatePerasCert mkPerasParams cert
   => validatePerasCert returns Right (ValidatedPerasCert cert (perasWeight params))
   (no signature check, no voter check, no quorum check)
4. The certificate is stored in the PerasCertDB / ChainDB.
5. Chain selection applies perasWeight boost to the attacker-chosen block.
6. Honest nodes switch to the attacker's preferred chain.
```

The root cause is at: [6](#0-5) 

called unconditionally from: [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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
