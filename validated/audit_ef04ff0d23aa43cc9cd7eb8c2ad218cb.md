### Title
Unconditional `validatePerasCert` Acceptance Bypasses All Peras Certificate Verification, Enabling Unauthorized Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. An unprivileged peer can send a crafted `PerasCert` pointing to any block, have it accepted as "validated," and cause the receiving node to apply a Peras weight boost to an attacker-chosen block during chain selection — making the node prefer a non-canonical or attacker-controlled chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate that must authenticate a certificate before it is stored and used in chain selection. The sole production instance (the `StandardHash blk` catch-all instance, lines 320–389) implements this gate as a stub that always succeeds:

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

No check is performed on:
- The aggregate BLS signature over the election identifier and boosted block
- Voter eligibility or committee membership
- Round number plausibility
- Whether the boosted block is a known, valid block

The inbound certificate pipeline in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then calls this validator on every inbound cert from a peer, and on success immediately forwards the result to `addPerasCertAsync` (or `addCert`), which stores it and triggers chain selection: [3](#0-2) 

The ChainDB `addPerasCertAsync` path then applies the `vpcCertBoost` weight to the boosted block during chain selection: [4](#0-3) 

**Attacker-controlled entry path:**

1. Attacker connects to a node as a normal peer via the Peras certificate ObjectDiffusion mini-protocol (no privileged access required).
2. Attacker sends a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block hash the attacker wants boosted.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → unconditionally returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
4. The cert is timestamped and passed to `addPerasCertAsync chainDB`.
5. Chain selection applies `perasWeight` boost to the attacker-chosen block, potentially causing the node to switch to a non-canonical fork.

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate verification enabling unauthorized certificate acceptance and chain-selection manipulation.**

The Peras protocol's security model depends entirely on certificates being unforgeable: only a quorum of legitimately elected committee members can produce a valid certificate. By accepting any certificate without signature or eligibility verification, an unprivileged peer can:

- Force an honest node to apply a Peras weight boost to an arbitrary block, including one on a minority or attacker-controlled fork.
- Cause the node to prefer a non-canonical chain over the honest chain, violating chain-selection safety.
- Permanently store a fraudulent certificate in the `PerasCertDB`, which persists across restarts and continues to influence chain selection.

This directly matches the allowed impact scope: *"Bypass of … certificate … checks … that enables unauthorized … certificate acceptance"* and *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

**Likelihood: High.**

- The attack requires only a standard peer connection — no keys, no stake, no privileged access.
- The ObjectDiffusion mini-protocol for Peras certificates is a public-facing network interface.
- The stub is the **only** production instance of `BlockSupportsPeras`; there is no fallback or secondary check.
- The TODO comment and linked issue (`cardano-peras/issues/120`) confirm the missing validation is a known gap, not an intentional design choice.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with full cryptographic and semantic validation before this code is deployed to any network that activates Peras. At minimum, the implementation must:

1. Verify the aggregate BLS signature (`pcSignature`) over the election identifier and boosted block hash using the public keys of the claimed voters.
2. Verify each claimed voter's committee eligibility (persistent or non-persistent membership via VRF proof).
3. Verify the round number is within the expected window for the current epoch.
4. Verify the boosted block is a known block in the local chain fragment.

Until the real implementation is in place, the inbound certificate pipeline should reject all certificates at the network boundary (return `Left PerasValidationErr` unconditionally) rather than accept them all.

---

### Proof of Concept

**Deterministic reasoning (no running node required):**

```
Peer sends PerasCert { pcCertRound = R, pcCertBoostedBlock = B_attacker }
  → processCerts calls: validatePerasCert mkPerasParams cert
  → validatePerasCert returns: Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })
  → processCerts calls: addCert (WithArrivalTime now validatedCert)
  → ChainDB stores cert and applies perasWeight boost to B_attacker in chain selection
  → Node may switch to the fork containing B_attacker
```

The unconditional `Right` at line 354 of `SupportsPeras.hs` is the sole gate, and it never fails. No cryptographic material is inspected. Any peer-supplied `PerasCert` value passes validation. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
