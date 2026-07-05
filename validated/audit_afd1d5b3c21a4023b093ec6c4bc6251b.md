### Title
Unconditional Peras Certificate Acceptance Bypasses Committee Validation, Enabling Unauthorized Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used in production certificate ingestion unconditionally accepts every inbound Peras certificate without checking committee membership, cryptographic signatures, or any other validity criterion. An unprivileged peer can therefore inject a crafted certificate that boosts an arbitrary block, triggering chain selection and causing an honest node to prefer a non-canonical chain.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides a stub `validatePerasCert` that unconditionally returns `Right`:

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

This stub is wired directly into the production certificate-ingestion pipeline. In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`, both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` pass `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass, adds them via `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` never returns `Left`, every certificate from every peer passes. The accepted certificate is then handed to `ChainDB.addPerasCertAsync`, which feeds into `chainSelSync` in `ChainDB/Impl/ChainSel.hs`. There, the certificate's boosted block is looked up in the `VolatileDB` and `chainSelectionForBlock` is triggered for it:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, so the boosted block's chain fragment gains the full Peras weight boost during comparison, potentially making a candidate chain heavier than the current selection.

The analog to the external report is exact: just as `addCollateral()` accepts tokens for any address without checking whitelist membership, `validatePerasCert` accepts any certificate without checking that the claimed voters are registered committee members.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as the boosted block and any round number. The certificate passes `validatePerasCert` unconditionally, is stored in the `PerasCertDB`, and triggers `chainSelectionForBlock` for the named block. If that block is in the node's `VolatileDB` (i.e., it was received but not yet selected), the artificial weight boost can cause the node to switch to a fork it would otherwise reject, violating chain-selection safety. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions. [5](#0-4) 

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a public, peer-facing interface. Any connected peer can submit a batch of certificates. No authentication, stake ownership, or prior block-production privilege is required to reach `processCerts`. The only existing guard is a duplicate-round check (`Set.member roundNo certIds`), which an attacker trivially bypasses by using a fresh round number. Likelihood is **High**. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies that every voter seat index in the certificate corresponds to a registered committee member in the current epoch's `VotingCommittee` (analogous to the whitelist check missing in the original report).
2. Verifies the aggregate BLS signature over the round number and boosted block hash against the public keys of the claimed voters.
3. Checks that the number of contributing voters and their combined stake meet the quorum threshold.

Until the full Cardano HFC plumbing is in place (tracked in `cardano-peras#73` and `#120`), the stub should at minimum reject all certificates rather than accept them unconditionally, so that the production node is not exposed to this manipulation vector. [7](#0-6) 

---

### Proof of Concept

**Setup:** Run a private two-node Cardano testnet with Peras enabled. Node A is the honest target; Node B is the attacker.

**Steps:**

1. Node B observes that Node A's `VolatileDB` contains block `B_fork` on a minority fork (e.g., one block behind the current tip).
2. Node B constructs a `PerasCert` with:
   - `pcCertRound` = any round number not yet in Node A's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of `B_fork`
   - Any placeholder signature field (the stub ignores it)
3. Node B sends this certificate to Node A via the object-diffusion mini-protocol.
4. Node A's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight params}`.
5. The certificate is stored and `addPerasCertAsync chainDB` is called.
6. `chainSelSync` looks up `B_fork` in the `VolatileDB`, finds it, and calls `chainSelectionForBlock` for it.
7. The chain containing `B_fork` now carries an extra `perasWeight` boost; if this exceeds the honest chain's lead, Node A switches to the fork.

**Expected (correct) behavior:** Step 4 should return `Left PerasValidationErr` because the certificate's voters are not registered committee members and the signature is invalid.

**Observed (buggy) behavior:** Step 4 returns `Right`, the certificate is accepted, and chain selection is manipulated. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
