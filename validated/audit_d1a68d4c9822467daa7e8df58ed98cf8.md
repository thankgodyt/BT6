### Title
`validatePerasCert` Degenerate Instance Unconditionally Accepts All Peras Certificates, Bypassing Certificate Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` type class defines `validatePerasCert` as the mandatory gate for verifying Peras certificates received from peers. A universal degenerate instance (`instance StandardHash blk => BlockSupportsPeras blk`) is the only instance in the codebase and its `validatePerasCert` implementation unconditionally returns `Right` — accepting every certificate without performing any cryptographic or eligibility check. The production inbound-certificate pipeline (`processCerts`) calls this function and relies on it to reject invalid certificates and disconnect misbehaving peers; because the function never rejects, any unprivileged peer can inject arbitrary Peras certificates that are stored in the `PerasCertDB` / `ChainDB` and subsequently influence chain selection.

---

### Finding Description

**Root cause — stub implementation that always succeeds**

`BlockSupportsPeras` declares `validatePerasCert` as the cryptographic gate for inbound certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the entire codebase is the universal degenerate one:

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

No cryptographic signature check, no committee eligibility check, no quorum threshold check — the function wraps the raw certificate in `Right` and returns it as "validated". [1](#0-0) 

Because this is a universal instance (`StandardHash blk => BlockSupportsPeras blk`) and no era-specific override exists anywhere in `ouroboros-consensus-cardano`, it is the instance resolved for all production Cardano block types. A grep of `ouroboros-consensus-cardano/src/**/*.hs` for `validatePerasCert` returns zero matches, confirming no override is present.

**Production call site — `processCerts`**

The inbound-certificate handler in `PerasCert.hs` passes `validatePerasCert mkPerasParams` directly as the validation callback:

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
``` [2](#0-1) 

`processCerts` is designed to reject the entire batch and throw `PerasCertValidationError` (causing peer disconnection) when any certificate fails validation. Because `validatePerasCert` never returns `Left`, the rejection branch is permanently dead:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  -- All certs are valid => add them to the pool
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  -- Some certs are invalid => reject the whole batch
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Every certificate — regardless of its cryptographic content — reaches `addCert . WithArrivalTime now` and is stored in the `ChainDB` via `addPerasCertAsync`. [4](#0-3) 

**Secondary broken check — `validatePerasVote`**

The same degenerate instance provides `validatePerasVote`, which skips all cryptographic signature verification and only checks stake-table membership:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [5](#0-4) 

Any peer that knows a valid pool ID can forge votes for arbitrary blocks and have them accepted by `PerasVote.hs`'s inbound pipeline, which calls `validatePerasVote` in the same pattern. [6](#0-5) 

---

### Impact Explanation

Peras certificates are the mechanism by which the Peras protocol boosts specific blocks during chain selection. A certificate for round `r` boosting block `B` causes honest nodes to prefer any chain that includes `B` over competing chains that do not, by adding `perasWeight` to `B`'s effective chain weight.

Because `validatePerasCert` unconditionally accepts every inbound certificate:

1. An unprivileged peer can inject a certificate boosting any block it chooses — including a block on an adversarial fork.
2. The certificate is stored in the `ChainDB` and applied during chain selection.
3. Honest nodes can be made to prefer a non-canonical, adversary-controlled chain over the honest chain, violating chain-selection safety.

This maps to the **High** impact category: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

It also partially maps to **Critical**: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

- **No privilege required**: any peer that can open a connection and speak the ObjectDiffusion mini-protocol can send certificates.
- **No cryptographic work required**: the attacker does not need to forge a valid BLS aggregate signature or satisfy VRF sortition; the check is simply absent.
- **Reachable in the current codebase**: `processCerts` is wired into the production `makePerasCertPoolWriterFromChainDB` path, which is the path used by the node kernel.
- The only mitigating factor is that Peras is not yet activated on mainnet; however, the code is present and the pipeline is live for any node running this version.

---

### Recommendation

Replace the degenerate universal instance with a proper per-era instance (or a `newtype` wrapper) that performs full cryptographic verification before the Peras feature is activated. Until then, `validatePerasCert` should at minimum return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the security posture is fail-closed rather than fail-open. The existing TODO at `https://github.com/tweag/cardano-peras/issues/120` tracks this work and should be treated as a security-blocking item.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the ObjectDiffusion mini-protocol for Peras certificates.
2. Construct a `PerasCert` value with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on an adversarial fork (no valid BLS signature needed).
3. Send the certificate in a batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which resolves to the degenerate instance and returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
5. `partitionEithers` produces `([], [validatedCert])` — the rejection branch is never taken.
6. `addCert (WithArrivalTime now validatedCert)` stores the certificate in the `ChainDB`.
7. Chain selection now applies the Peras boost to the adversary's chosen block, causing the node to prefer the adversarial fork over the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```
