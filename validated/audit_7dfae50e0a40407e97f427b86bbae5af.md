### Title
Peras Vote Validation Excludes Cryptographic Signature Check, Enabling Forged Vote and Certificate Acceptance — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasVote` checks voter stake-distribution membership but **excludes** cryptographic signature verification entirely. This is the direct analog of the external report's pattern: `inspect()` returns some arguments (`to`, `token`, `dex`) but omits the critical ones (`amount`, `minReturn`). Here, the validation checks the voter identity/stake but omits the vote signature, so any peer can submit a structurally valid-looking vote with a forged signature and have it accepted. Compounding this, `validatePerasCert` is a stub that accepts every certificate unconditionally. Both functions are wired into the live network ingest path via `processCerts`.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the catch-all `BlockSupportsPeras` instance (explicitly noted as the "degenerate instance for all blks to get things to compile") implements two validation functions:

**`validatePerasVote`** — checks only stake-distribution membership, omitting signature verification:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The `_params` argument (which carries the cryptographic configuration) is discarded with `_`. No signature over `(electionId, candidate)` is verified. Any peer who knows a valid voter ID can submit a vote with an arbitrary forged signature and receive a `Right ValidatedPerasVote`.

**`validatePerasCert`** — unconditionally accepts every certificate:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No field of the certificate (`pcRoundNo`, `pcBoostedBlock`, `pcVoters`, `pcSignature`) is inspected.

These functions are called from the live network ingest path. `processCerts` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` is invoked by both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` with `validatePerasCert mkPerasParams` as the validator:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (PerasCertDB.getCertIds perasCertDB)
      (validatePerasCert mkPerasParams)   -- stub accepts everything
      (void . join . atomically . PerasCertDB.addCert perasCertDB)
      certs
```

`processCerts` then stores every certificate that passes this non-validation into the `PerasCertDB`, from which `getWeightSnapshot` feeds the Peras chain-selection boost.

---

### Impact Explanation

Peras certificates boost specific blocks during chain selection. A certificate stored in `PerasCertDB` increases the effective weight of the block it references. Because `validatePerasCert` accepts any certificate unconditionally, an unprivileged peer can:

1. Craft a `PerasCert` pointing `pcBoostedBlock` at any block on any fork.
2. Send it via the object-diffusion mini-protocol.
3. Have it stored in `PerasCertDB` and reflected in `getWeightSnapshot`.
4. Cause honest nodes to prefer a non-canonical or adversarially chosen chain.

This is a **Critical** bypass of Peras certificate validation that enables unauthorized certificate acceptance and chain-selection manipulation, matching the allowed impact scope: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

The attack requires no special privileges, no stake majority, and no key compromise. Any peer participating in the object-diffusion mini-protocol can send crafted certificates. The degenerate instance is the only `BlockSupportsPeras` instance currently compiled for all block types, so there is no override that would restore proper validation. Likelihood is **High**.

---

### Recommendation

1. Implement full cryptographic validation in `validatePerasCert`: verify the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)` against the aggregate verification key derived from the declared voters, and verify each non-persistent voter's VRF output.
2. Implement signature verification in `validatePerasVote`: verify the vote signature over `(electionId, candidate)` using the voter's public key from the stake distribution before returning `Right`.
3. Until proper implementations exist, the object-diffusion ingest path should not store certificates/votes that have not passed full cryptographic validation. Consider gating `processCerts` behind a feature flag that rejects all certificates while the stub is in place.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  1. Construct PerasCert {
  │       pcRoundNo      = <any round>,
  │       pcBoostedBlock = <target adversarial block hash>,
  │       pcVoters       = <any bitmap>,
  │       pcSignature    = <garbage / zeroed BLS signature>
  │     }
  │
  │  2. Send via object-diffusion mini-protocol to honest node
  │
  ▼
makePerasCertPoolWriterFromChainDB / makePerasCertPoolWriterFromCertDB
  │
  │  3. processCerts called with (validatePerasCert mkPerasParams)
  │
  ▼
validatePerasCert params cert
  = Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
  -- no signature check, no voter check, no round check
  │
  │  4. Certificate stored in PerasCertDB
  │
  ▼
getWeightSnapshot
  -- adversarial block now carries Peras boost weight
  │
  │  5. Chain selection prefers adversarially boosted fork
  │
  ▼
Honest node adopts non-canonical chain
```

**Relevant source locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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
```
