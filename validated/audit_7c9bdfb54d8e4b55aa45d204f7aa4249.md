### Title
Peras Certificate Validation Bypass: Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` method is a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic validation. This stub is wired directly into the production inbound-certificate processing path (`makePerasCertPoolWriterFromChainDB` → `processCerts`). Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted-block pointer; the certificate will pass "validation," be inserted into the `PerasCertDB`, and trigger chain selection with an attacker-controlled Peras weight boost applied to an arbitrary block.

---

### Finding Description

**Root cause — stub validation that always succeeds**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate before a certificate is accepted. The only deployed instance is the catch-all degenerate one:

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

Every call to `validatePerasCert` returns `Right` regardless of the certificate's content. No committee membership check, no signature verification, no round-number bounds check, and no boosted-block existence check is performed.

**Production inbound path that calls the stub**

`makePerasCertPoolWriterFromChainDB` constructs the `ObjectPoolWriter` used for all peer-supplied Peras certificates. Its `opwAddObjects` field calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, if all pass (which they always do), forwards them to `addCert` / `ChainDB.addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` never produces a `Left`, the error branch is unreachable and every peer-supplied certificate is unconditionally accepted.

**Chain selection consequence**

`ChainDB.addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. When processed by `chainSelSync`, the certificate's `vpcCertBoost` (set to `perasWeight params` by the stub) is applied to the boosted block via the `PerasWeightSnapshot`, directly influencing `preferAnchoredCandidate` and potentially causing the node to switch to a fork that carries the attacker-chosen block. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can inject a `PerasCert` naming any block as the Peras-boosted block for any round. The node's chain-selection logic will apply the configured `perasWeight` boost to that block. If the attacker's chosen block is on a competing fork, the honest node may switch to that fork even though it would not have been preferred under the unweighted Praos chain-order rule. This constitutes a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain**, matching the High impact tier. It also constitutes a **bypass of Peras certificate checks that enables unauthorized certificate acceptance**, matching the Critical tier.

---

### Likelihood Explanation

The Peras certificate ObjectDiffusion mini-protocol is a standard node-to-node protocol reachable by any peer that can establish a connection. No stake, key material, or privileged access is required. The attacker only needs to craft a `PerasCert` CBOR value with a desired `pcCertRound` and `pcCertBoostedBlock` and send it over the protocol. The stub is the only deployed instance; there is no fallback real validator.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion path is enabled in production. At minimum, the validator must:

1. Verify that the certificate's committee signatures are valid and come from eligible committee members for the claimed round.
2. Verify that the boosted block exists and is within the valid slot range for the round.
3. Verify that the certificate's round number is within the acceptable window relative to the current chain tip.

Until real validation is implemented, the inbound certificate processing path (`makePerasCertPoolWriterFromChainDB`) should be disabled or gated behind a feature flag that is off by default on production nodes.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Connect to a target node as a peer via the Peras certificate ObjectDiffusion mini-protocol.
2. Craft a `PerasCert` value:
   - `pcCertRound`: any round number not yet present in the node's `PerasCertDB` (to bypass the deduplication check at line 166 of `PerasCert.hs`).
   - `pcCertBoostedBlock`: the `Point` of a block on a competing fork that the attacker wants the node to prefer.
3. Send the certificate in a batch via `opwAddObjects`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is passed to `ChainDB.addPerasCertAsync`, enqueuing a `ChainSelAddPerasCert` message.
6. `chainSelSync` processes the message, updates the `PerasWeightSnapshot` with the boost for the attacker-chosen block, and re-runs chain selection.
7. If the boosted block is on a fork that is now heavier than the current selection, the node switches to that fork.

**Expected outcome:** The honest node adopts a chain that it would not have selected under the unmanipulated Praos chain-order rule, driven entirely by a fabricated Peras certificate supplied by an unprivileged peer. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```
