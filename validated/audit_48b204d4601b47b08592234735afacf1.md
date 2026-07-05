### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Always Returning Success - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) for every certificate received, regardless of the aggregate BLS signature, voter eligibility proofs, or quorum. Any unprivileged peer can send a crafted `PerasCert` over the ObjectDiffusion mini-protocol, have it accepted as a `ValidatedPerasCert`, stored in `PerasCertDB`, and have its weight boost applied to an arbitrary block during chain selection. This is the direct analog of the biometric bypass: the "authentication succeeded" result is returned without ever verifying the cryptographic object.

---

### Finding Description

**Root cause — stub validator always succeeds:**

The `BlockSupportsPeras` class defines `validatePerasCert` as the mandatory cryptographic gate before a certificate may be stored as `ValidatedPerasCert`. The only active instance is the degenerate catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

No BLS aggregate signature check, no VRF eligibility proof check, no quorum threshold check — the function wraps any input cert in `ValidatedPerasCert` and returns it.

**Inbound path — production pool writer calls this stub:**

`makePerasCertPoolWriterFromChainDB` (explicitly described as "for actual production use") calls `processCerts` with this stub as the validator:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound cert; if all return `Right`, they are timestamped and stored:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because the stub always returns `Right`, the `(errs, _)` branch is unreachable. Every cert passes.

**Storage — `implAddCert` also carries a TODO for non-trivial validation:**

Even at the DB layer, the comment confirms no validation is performed:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert :: ...
``` [4](#0-3) 

**Chain selection impact — stored certs directly feed weight snapshots:**

`getWeightSnapshot` returns a `PerasWeightSnapshot` built from every certificate in the DB, keyed by the boosted block point. This snapshot is used to compare candidate chains:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [5](#0-4) 

A fake certificate boosting an attacker-chosen block point will cause that block to appear heavier than the honest chain tip during Peras-aware chain selection.

**Serialization note confirms crypto checks are deferred (and never arrive):**

```
-- NOTE: the validation performed during serialization is minimal, and does not
-- cover any of additional semantic and cryptographic checks that must be
-- performed on the certificate later on.
``` [6](#0-5) 

"Later on" never happens because `validatePerasCert` is the stub.

---

### Impact Explanation

**High — chain selection bug via unprivileged peer input.**

A peer sends a crafted `PerasCert` (valid CBOR structure, arbitrary `pcBoostedBlock`, fabricated `pcSignature`) over the ObjectDiffusion mini-protocol. The node accepts it as `ValidatedPerasCert`, stores it in `PerasCertDB`, and the resulting `PerasWeightSnapshot` assigns a Peras boost to the attacker-chosen block. The honest node's chain selection then prefers a non-canonical or adversarially-chosen chain over the honest chain, violating the Peras safety guarantee that only quorum-certified blocks receive a boost.

This matches the allowed impact scope: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Medium.** The ObjectDiffusion mini-protocol for Peras certificates is a live production code path (`makePerasCertPoolWriterFromChainDB`). Any peer that can connect to the node can submit certificates. Constructing a structurally valid CBOR-encoded `PerasCert` with an arbitrary boosted block and a placeholder BLS signature requires no privileged access — only knowledge of the wire format, which is public. The only friction is that the Peras protocol extension may not yet be activated on mainnet, but the code is compiled and wired into the node binary.

---

### Recommendation

1. **Remove the degenerate stub instance.** The `instance StandardHash blk => BlockSupportsPeras blk` must not be the active instance for production Cardano blocks. A proper Cardano-specific instance must implement `validatePerasCert` to verify: (a) the aggregate BLS signature over `(roundNo, boostedBlock)`, (b) each voter's VRF eligibility proof against the committee, and (c) that the total stake of attesting voters meets the quorum threshold.

2. **Gate `processCerts` on a real validator.** Until the real instance exists, `processCerts` should not be wired into the production `makePerasCertPoolWriterFromChainDB`. The TODO placeholder `(validatePerasCert mkPerasParams)` must be replaced before the Peras diffusion path is enabled.

3. **Add a type-level or runtime guard.** Consider using a `newtype` wrapper or phantom type to prevent a `PerasCert` from being stored as `ValidatedPerasCert` without passing through a non-stub validator, analogous to how `CryptoObject` in Android Keystore cryptographically binds the authentication result to a hardware-backed key.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Connect to a Cardano node as an unprivileged peer via the ObjectDiffusion mini-protocol for Peras certificates.
2. Construct a CBOR-encoded `PerasCert` (per `Ouroboros.Consensus.Peras.Cert.V1`) with:
   - `pcRoundNo`: any valid round number not already in the DB
   - `pcBoostedBlock`: the hash of a non-canonical block the attacker wants to boost
   - `pcVoters`: a minimal valid bitmap (at least one bit set)
   - `pcSignature`: any bytes that deserialize as an `AggregateVoteSignature`
3. Send the cert to the target node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The cert is stored in `PerasCertDB` via `addCert`.
6. `getWeightSnapshot` now returns a boost for `pcBoostedBlock`.
7. The node's Peras-aware chain selection assigns the boost weight to the attacker-chosen block, causing it to be preferred over the honest chain tip.

**Expected outcome:** The honest node selects a non-canonical chain boosted by the fake certificate, diverging from the rest of the honest network.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L10-13)
```haskell
--
-- NOTE: the validation performed during serialization is minimal, and does not
-- cover any of additional semantic and cryptographic checks that must be
-- performed on the certificate later on.
```
