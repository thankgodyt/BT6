### Title
`validatePerasCert` Unconditionally Accepts Any Peras Certificate Without Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that always returns `Right` (success) without performing any cryptographic or structural validation. This is the only instance of `BlockSupportsPeras` in the codebase and is wired directly into the production certificate ingestion path (`processCerts` → `ChainDB.addPerasCertAsync`). An unprivileged peer can send crafted Peras certificates with arbitrary round numbers and arbitrary boosted block points, and they will be unconditionally accepted and stored, enabling manipulation of Peras-weighted chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the sole `BlockSupportsPeras` instance (the degenerate catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements `validatePerasCert` as:

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

This function accepts every certificate unconditionally. The `PerasCert` data type itself carries no signature field:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

**Production call path:**

`validatePerasCert` is called directly in the production certificate pool writer wired to the `ChainDB`:

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
``` [3](#0-2) 

Inside `processCerts`, the validation result is the sole gate before `addCert` is called:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never taken. Every inbound certificate from every peer is accepted and forwarded to `ChainDB.addPerasCertAsync`.

**Analog to the external report:**

The external report describes a guard (`checkTransaction`) that checks `data.length < 4` but fails to handle the `data.length == 0` edge case — an incomplete condition that blocks valid inputs. The analog here is the inverse: `validatePerasCert` has no condition at all, making it an incomplete guard that passes all inputs, including invalid/crafted ones. Both are incomplete validation checks on a security-critical gate function.

---

### Impact Explanation

Peras certificates boost the weight of specific blocks during chain selection. A certificate for block `B` at round `R` causes honest nodes to prefer chains containing `B` over chains of equal or slightly greater length that do not. By injecting crafted certificates with arbitrary `pcCertBoostedBlock` values, an unprivileged peer can:

1. **Cause honest nodes to prefer a non-canonical chain** — by boosting a block on an adversarial fork, the attacker can make the node's chain selection diverge from the honest majority chain.
2. **Bypass Peras certificate authorization entirely** — no quorum of legitimate committee votes is required; a single peer message suffices to inject a "validated" certificate.

This matches the **Critical** impact category: bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The attack requires only the ability to connect as a peer and send a `PerasCert` message via the Peras certificate mini-protocol. No stake, no keys, and no privileged access are required. The `processCerts` function is the sole validation gate, and it is completely bypassed. Likelihood is **High** for any node running with Peras certificate diffusion enabled.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature over the claimed voters' public keys.
2. That the claimed voters constitute a valid quorum (sufficient stake) from the current committee.
3. That `pcCertBoostedBlock` refers to a block that actually exists on a known chain fragment.

Until real validation is implemented, the certificate pool writer should not be wired to the `ChainDB` in production builds, or the `processCerts` path should be gated behind a feature flag that is disabled by default.

---

### Proof of Concept

A peer connects to a node and sends a batch containing a single crafted certificate:

```
PerasCert
  { pcCertRound      = <any round number, e.g. current round>
  , pcCertBoostedBlock = <point of an adversarial fork block>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams cert`, which returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }
```

The `([], validatedCerts)` branch is taken, and `ChainDB.addPerasCertAsync chainDB` is called with the crafted certificate. The ChainDB now holds a certificate boosting the adversarial block, and subsequent chain selection will weight that block accordingly — without any legitimate quorum of committee votes having been cast. [5](#0-4) [6](#0-5)

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
