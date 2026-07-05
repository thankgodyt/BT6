### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance for all block types contains a degenerate `validatePerasCert` implementation that unconditionally returns `Right` (success) for every certificate it receives, with no cryptographic or structural checks performed. This stub is wired directly into the live Peras certificate ingest pipeline (`processCerts`), meaning any unprivileged peer can inject arbitrary Peras certificates that will be stored and used to boost attacker-chosen blocks during chain selection.

---

### Finding Description

In `SupportsPeras.hs`, the universal `BlockSupportsPeras` instance is explicitly marked as a temporary degenerate placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Its `validatePerasCert` method carries an explicit TODO and performs zero validation — it unconditionally returns `Right` for every certificate, assigning it the full configured Peras boost weight:

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
``` [2](#0-1) 

This function is not dead code. It is passed directly as the `validateCert` argument in both production pool-writer constructors in `PerasCert.hs`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [4](#0-3) 

The `processCerts` function calls `validateCert` on each inbound certificate and, if all pass, stores them via `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [5](#0-4) 

Because `validatePerasCert` never produces a `Left`, the error branch is unreachable. Every certificate from every peer is stored unconditionally.

The same pattern applies to `validatePerasVote`, which also carries a TODO and performs no cryptographic signature verification — it only checks stake-distribution membership: [6](#0-5) 

---

### Impact Explanation

Peras certificates are used to apply a configurable weight boost (`perasWeight`) to a specific block during chain selection. A node that stores a forged certificate for an attacker-chosen block will treat that block as having higher chain weight than it actually does. This can cause the node to prefer a non-canonical or adversarially-chosen chain over the honest chain, constituting a **chain-selection manipulation** that violates the safety guarantees of the Ouroboros Peras protocol.

This matches the **High** impact category: *Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

The attacker-controlled entry path is the Peras object-diffusion mini-protocol. Any peer connected to the node can send a `PerasCert` message. The certificate is deserialized, deduplicated against the DB, and then passed to `validatePerasCert` — which always succeeds. No privilege, key material, or stake is required. The path is direct and requires no preconditions beyond establishing a peer connection.

---

### Recommendation

The degenerate `BlockSupportsPeras` instance must not be used in any production code path that accepts inbound certificates from peers. Until a real cryptographic implementation is in place (per [issue #120](https://github.com/tweag/cardano-peras/issues/120) and [issue #73](https://github.com/tweag/cardano-peras/issues/73)), the `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` constructors should either:

1. Refuse to construct a writer when no real validator is available (return an error or `Nothing`), or
2. Be gated behind a feature flag that is disabled in production builds until the real `validatePerasCert` implementation is wired in.

The same applies to `validatePerasVote`, which must verify the cryptographic signature of each vote before accepting it.

---

### Proof of Concept

1. A peer connects to a node running this code.
2. The peer sends a `PerasCert` message containing a certificate for an arbitrary block `B` (e.g., a block on a minority fork).
3. `processCerts` is called; `validatePerasCert mkPerasParams cert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is stored in `PerasCertDB` / `ChainDB` with the full Peras boost weight.
5. During chain selection, block `B` now carries an artificial weight boost equal to `perasWeight params`, causing the node to prefer the fork containing `B` over the honest chain.
6. The node has been made to select a non-canonical chain without the attacker possessing any keys, stake, or operator access. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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
