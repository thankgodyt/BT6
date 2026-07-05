### Title
`validatePerasCert` Stub Unconditionally Accepts All Peras Certificates Without Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance provides a `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural validation whatsoever. The `processCerts` inbound pipeline correctly delegates to this function, but since the function never rejects, any certificate crafted by an unprivileged peer is silently accepted and stored in the `PerasCertDB`, where it influences Peras-weighted chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The production default instance, which applies to all block types (`StandardHash blk => BlockSupportsPeras blk`), is a stub that always returns `Right`:

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

The inbound certificate pipeline in `processCerts` correctly calls `validateCert` (bound to `validatePerasCert mkPerasParams`) and would throw a `PerasCertValidationError` if any certificate returned `Left`. Because the stub never returns `Left`, the error branch is unreachable:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

The `makePerasCertPoolWriterFromChainDB` function wires this pipeline directly to the peer-facing object-diffusion inbound path: [3](#0-2) 

Accepted certificates are stored in the `PerasCertDB` and immediately influence chain selection via `getWeightSnapshot`, which returns Peras boost weights used to prefer candidate chains: [4](#0-3) 

The structural parallel to M-09 is exact: `processCerts` plays the role of `tokenURI` — it correctly delegates to an inner validation function — but the inner function (`validatePerasCert`) performs no check, just as `nftRenderer.render` was not guaranteed to check token existence. The outer function's correctness is entirely contingent on the inner function's correctness, and the inner function is a no-op stub in production code.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` (any `Point blk`). Because `validatePerasCert` always returns `Right`, the certificate bypasses all validation — no committee membership check, no BLS/signature verification, no round-number plausibility check — and is stored in the `PerasCertDB`. The stored certificate contributes a `perasWeight`-sized boost to the nominated block in `getWeightSnapshot`, which is consumed by chain selection. A peer can therefore inject artificial weight onto any block point it chooses, potentially causing an honest node to prefer a non-canonical or adversarially-chosen chain over the honest chain.

This matches the allowed impact: **Critical — bypass of Peras certificate checks that enables unauthorized certificate acceptance**, and **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The entry path is the Peras certificate object-diffusion miniprotocol, reachable by any connected peer without any privilege. The peer need only send a well-formed (but cryptographically invalid) `PerasCert` message. No key compromise, stake majority, or operator action is required. The only limiting factor is that Peras is not yet activated on mainnet; however, the stub is in the production code path today, and activation without fixing this stub would immediately expose every node to the attack.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that performs at minimum:

1. **Committee membership check**: verify the certificate was produced by a legitimately elected committee for the claimed round.
2. **Cryptographic signature/BLS aggregate verification**: verify the certificate's aggregate signature over the claimed block point and round number.
3. **Round plausibility check**: verify the round number is within an acceptable window relative to the current chain tip.

Until a real implementation is available, the stub should be removed from the default `BlockSupportsPeras` instance so that the code does not compile for production block types without an explicit, reviewed implementation. The `processCerts` function itself is structurally correct and requires no changes.

---

### Proof of Concept

A peer connected via the Peras certificate object-diffusion protocol sends a batch containing one `PerasCert`:

```
PerasCert
  { pcCertRound       = PerasRoundNo 999999   -- arbitrary future round
  , pcCertBoostedBlock = someAdversarialPoint  -- any Point blk
  }
```

Execution path:

1. `makePerasCertPoolWriterFromChainDB` receives the batch via `opwAddObjects`.
2. `processCerts` filters out already-known round numbers (none match `999999`).
3. `validatePerasCert mkPerasParams cert` is called → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. `partitionEithers` yields `([], [validatedCert])` → the `(errs, _)` branch is never taken.
5. `addCert (WithArrivalTime now validatedCert)` stores the certificate in `PerasCertDB`.
6. `getWeightSnapshot` now includes a boost for `someAdversarialPoint`, influencing chain selection on the victim node. [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```
