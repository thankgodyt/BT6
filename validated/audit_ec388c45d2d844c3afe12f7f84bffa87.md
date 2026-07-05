### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation, Enabling Unauthorized Chain-Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum checks. This function is wired directly into the production Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer connected via the Peras object-diffusion miniprotocol can inject arbitrary `PerasCert` values that boost any block of their choosing, causing the receiving node to prefer a non-canonical chain during chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the only `BlockSupportsPeras` instance is a degenerate catch-all:

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
```

This function accepts every certificate unconditionally — no aggregate BLS signature check, no voter eligibility check, no quorum threshold check, no epoch-nonce binding.

**Production ingest path wires this stub directly:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`, `makePerasCertPoolWriterFromChainDB` — the production writer used for peer-received certificates — passes this stub as the validator:

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
```

**`processCerts` trusts the validator's result:**

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

Because `validateCert` never returns a `Left`, the `([], validatedCerts)` branch is always taken and every peer-supplied certificate is stored.

**Chain selection consumes the injected certificates:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs`, the `readChainComparison` function feeds the `PerasWeightSnapshot` — which is built from stored certificates — directly into `compareCandidateChains`:

```haskell
readChainComparison =
  fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
 where
  mkChainComparison weights =
    ChainComparison
      { plausibleCandidateChain = plausibleCandidateChain weights
      , compareCandidateChains  = compareCandidateChains  weights
      }
```

A fake certificate boosting an attacker-controlled block therefore directly shifts the chain-comparison outcome in favour of the attacker's fork.

---

### Impact Explanation

**Severity: High — Chain-selection manipulation by an unprivileged peer.**

An attacker with a single peer connection can craft a `PerasCert` naming any `(roundNo, boostedBlock)` pair. Because `validatePerasCert` never rejects it, the certificate is stored in the `PerasCertDB` / `ChainDB` and its boost weight is included in every subsequent chain-comparison. The attacker can therefore cause an honest node to prefer a non-canonical or adversarial fork over the honest chain, violating the Peras security assumption that only legitimately quorum-certified blocks receive a boost.

This matches the allowed impact category: *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**High.** The attack requires only a standard peer connection and the ability to send a well-formed CBOR-encoded `PerasCert` message over the Peras object-diffusion miniprotocol. No keys, stake, or privileged access are needed. The stub is the only `BlockSupportsPeras` instance in the codebase and is unconditionally selected for all block types.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(roundNo, boostedBlock)` against the claimed voters' public keys.
2. Checks each claimed voter's eligibility against the current epoch's stake distribution and committee selection (VRF output for non-persistent members).
3. Confirms the total stake of eligible voters meets the quorum threshold.
4. Binds the certificate to the correct epoch nonce so certificates from a different epoch cannot be replayed.

Until the real implementation is in place, the production path in `makePerasCertPoolWriterFromChainDB` should reject all inbound certificates rather than accept them unconditionally.

---

### Proof of Concept

1. Attacker connects to a victim node as a normal peer.
2. Attacker sends a Peras object-diffusion message containing a `PerasCert` with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <point of attacker's preferred fork tip>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams}` without any checks.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. On the next chain-selection event, `getPerasWeightSnapshot` returns a snapshot that includes the fake boost for the attacker's block.
6. `compareCandidateChains` now prefers the attacker's fork, causing the victim node to switch to the non-canonical chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-240)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
```
