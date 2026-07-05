### Title
Unconditional `validatePerasCert` Acceptance Bypasses All Peras Certificate Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Both production pool-writer paths (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) call this stub with the hardcoded `mkPerasParams` config. An unprivileged peer can therefore inject arbitrary `PerasCert` objects — for any round, boosting any block — that will be accepted, stored, and used to influence Peras chain selection.

### Finding Description
The degenerate `BlockSupportsPeras blk` instance in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional success:

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

This stub is the only instance in the codebase. Both production object-pool writers wire it directly into the inbound certificate processing pipeline:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

The `processCerts` function applies this validator to every inbound certificate not already in the DB. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch that would reject invalid certificates is never taken:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

The accepted `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` drawn from `mkPerasParams` (default `PerasWeight 15`), which is then used in Peras chain selection to boost the attacker-chosen block. [5](#0-4) 

The analog to the external report is exact: just as `liquidationThresholdPercent = 0` makes `belowMaintenanceThreshold` always true (every position is immediately liquidatable), `validatePerasCert = Right` makes every certificate immediately valid — the threshold check is vacuously satisfied regardless of the certificate's actual content.

### Impact Explanation
An unprivileged peer can send a crafted `PerasCert` naming any `(roundNo, blockPoint)` pair. The certificate bypasses all validation, is stored in the `PerasCertDB` / `ChainDB`, and its `PerasWeight 15` boost is applied during Peras chain selection. By injecting certificates that boost an adversary-controlled fork, the attacker can cause an honest node to prefer a non-canonical chain, violating chain-selection safety. This maps to: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions**, and also to **Critical — bypass of certificate validation that enables unauthorized certificate acceptance**.

### Likelihood Explanation
The object-diffusion mini-protocol for Peras certificates is wired into the production `NodeKernel` path. Any connected peer can send a `PerasCert` message. No stake, key material, or special privilege is required. The only prerequisite is a TCP connection to the node. Likelihood is **High** once Peras is activated on a network running this code.

### Recommendation
Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's quorum signature (BLS aggregate or equivalent) against the registered committee for the claimed round.
2. That the boosted block point exists and is within the valid age window (`perasCertMaxRounds`).
3. That the round number is within the acceptable range relative to the current tip.

Until real validation is implemented, the pool writers should not be wired into the live diffusion layer, or inbound certificates should be quarantined rather than immediately applied to chain selection.

### Proof of Concept
1. Connect to a node running this code via the Peras object-diffusion mini-protocol.
2. Send a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversaryBlockPoint }` for any round `r` and any block point.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
4. The cert is stored via `addCert` / `ChainDB.addPerasCertAsync`.
5. Peras chain selection now applies a weight-15 boost to `adversaryBlockPoint`, causing the node to prefer the adversary's chain over the honest chain whenever the honest chain's density advantage is less than 15 blocks. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
