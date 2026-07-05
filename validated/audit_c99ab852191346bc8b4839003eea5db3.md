### Title
`validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Because this function is the only gate between the object-diffusion mini-protocol inbound path and the `PerasCertDB` / chain-selection engine, any unprivileged peer can inject an arbitrary `PerasCert` — with any `pcCertRound` and any `pcCertBoostedBlock` — and have it accepted, stored, and acted upon by chain selection. This is the direct analog of the `VaultStrat.deposit` missing-access-control pattern: a function that is supposed to enforce authorization instead lets any caller bypass it entirely.

---

### Finding Description

**Root cause — `validatePerasCert` stub always returns `Right`**

The only `BlockSupportsPeras` instance in the codebase is a catch-all:

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

No signature check, no committee membership check, no round-number range check, no boosted-block existence check — the function simply wraps the raw peer-supplied `PerasCert` in a `ValidatedPerasCert` and returns it as valid.

**Inbound path — production `makePerasCertPoolWriterFromChainDB`**

The production writer for the object-diffusion mini-protocol calls `processCerts` with this stub as the validator:

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

`processCerts` partitions results into `(errors, validatedCerts)`. Because `validatePerasCert` never produces a `Left`, the error list is always empty and every peer-supplied cert is forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Chain-selection consequence — `chainSelSync` for `ChainSelAddPerasCert`**

Once the cert is enqueued, `chainSelSync` processes it:

1. Ignores the cert only if the boosted block's slot is older than the immutable tip.
2. Adds the cert to `PerasCertDB` (unconditionally, since it already passed "validation").
3. If the boosted block is **not** on the current chain but **is** present in the VolatileDB, calls `chainSelectionForBlock` for that block, triggering a full chain-selection run with the Peras weight boost applied. [4](#0-3) 

The `vpcCertBoost` field is set to `perasWeight params` — the full configured Peras weight — so the boosted fork gains the maximum possible weight advantage in chain selection.

---

### Impact Explanation

**Impact: High — chain-selection manipulation by an unprivileged peer.**

An attacker who can connect as a peer (no keys, no stake, no operator access required) can:

1. Observe which blocks are currently in the target node's VolatileDB on a competing fork (via ChainSync headers).
2. Craft a `PerasCert` whose `pcCertBoostedBlock` points to a block on that competing fork.
3. Send the cert via the object-diffusion mini-protocol.
4. Because `validatePerasCert` always returns `Right`, the cert is accepted, stored, and used to boost the competing fork's weight.
5. If the boosted fork's weight now exceeds the current chain's weight, `chainSelectionForBlock` switches the node to the non-canonical fork.

This lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions of the Peras protocol, which is precisely the "High" impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain*.

---

### Likelihood Explanation

**Likelihood: High.**

- The attack requires only a standard peer connection — no privileged keys, no stake, no operator access.
- The object-diffusion mini-protocol for Peras certs is the production path (`makePerasCertPoolWriterFromChainDB`), not a test stub.
- The stub `validatePerasCert` is the **only** `BlockSupportsPeras` instance (catch-all `instance StandardHash blk =>`), so there is no override for Cardano blocks.
- The attacker needs only to know a valid block hash in the target's VolatileDB, which is observable via ChainSync.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
- Verifies the certificate's cryptographic signature against the registered committee keys.
- Checks that the `pcCertRound` is within the valid range for the current epoch.
- Checks that the `pcCertBoostedBlock` corresponds to a block that was a valid candidate in the claimed round.
- Returns `Left (PerasValidationErr ...)` for any failure, causing `processCerts` to throw `PerasCertInboundException` and disconnect the offending peer.

Until the real implementation is in place, the Peras cert inbound path should be disabled or gated behind a feature flag so that no peer-supplied cert can influence chain selection.

---

### Proof of Concept

**Attacker preconditions:** peer connection only (no keys, no stake).

**Step 1 — Observe a competing fork block.**
Via ChainSync, the attacker learns that the target node's VolatileDB contains block `B` at slot `s` on a fork that is currently not selected.

**Step 2 — Craft a fake cert.**
```haskell
fakeCert :: PerasCert blk
fakeCert = PerasCert
  { pcCertRound    = someRecentRound   -- any round not yet in PerasCertDB
  , pcCertBoostedBlock = blockPoint B  -- the competing fork's block
  }
```

**Step 3 — Send via object diffusion.**
The attacker sends `[fakeCert]` through the object-diffusion mini-protocol.

**Step 4 — `validatePerasCert` accepts unconditionally.**
```haskell
validatePerasCert mkPerasParams fakeCert
-- = Right (ValidatedPerasCert { vpcCert = fakeCert, vpcCertBoost = perasWeight mkPerasParams })
``` [5](#0-4) 

**Step 5 — Cert is stored and chain selection is triggered.**
`ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` finds block `B` in the VolatileDB and calls `chainSelectionForBlock` with the Peras weight boost applied to `B`'s fork. [6](#0-5) 

**Step 6 — Node switches to non-canonical fork.**
If the boosted fork's weight now exceeds the current chain's weight, the node rolls back to the fork point and adopts the competing chain — driven entirely by the attacker's unauthenticated certificate.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
