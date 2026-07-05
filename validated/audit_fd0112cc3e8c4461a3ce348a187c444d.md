### Title
Peras Certificate Validation Unconditionally Returns Success, Enabling Unauthorized Certificate Acceptance and Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) without performing any cryptographic or semantic validation of inbound Peras certificates. This is the only deployed instance. Any unprivileged peer can send crafted certificates for arbitrary round numbers and block hashes; `processCerts` will accept them all, store them in the `PerasCertDB`, and trigger `chainSelectionForBlock` for the boosted block — potentially causing the node to switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

In the universal `BlockSupportsPeras` instance (the only instance in the codebase), `validatePerasCert` unconditionally wraps the input certificate in `Right ValidatedPerasCert` without inspecting any field:

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

This is the exact structural analog to the ERC20 `transfer` that silently returns `false`: the function is typed to signal failure via `Left`, but the implementation never produces `Left`, so the caller's rejection branch is dead code for all inputs.

**Inbound certificate processing uses this stub directly:**

`makePerasCertPoolWriterFromChainDB` — the production writer used by the object-diffusion mini-protocol — passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [2](#0-1) 

`processCerts` partitions results into `(errors, valids)`. Because `validatePerasCert` never produces `Left`, the error list is always empty and every certificate is forwarded to `addCert`:

```haskell
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Accepted certificates trigger chain selection:**

`chainSelSync` processes each accepted certificate. If the boosted block is present in the `VolatileDB`, it calls `chainSelectionForBlock` unconditionally:

```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The Peras weight boost assigned to the forged certificate (`perasWeight params`) is added to the candidate chain's weight, which can make a weaker fork appear heavier than the honest chain and cause the node to switch.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with any `pcCertRound` and `pcCertBoostedBlock`. Because `validatePerasCert` always returns `Right`, the certificate is stored in the `PerasCertDB` and its boost weight is applied to the target block during chain selection. If the boosted block is on a fork that is otherwise lighter than the current chain, the injected boost can flip the chain-selection comparison, causing the honest node to abandon its canonical chain and adopt the attacker's fork. This is a bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain selection manipulation.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer without authentication. The attacker only needs to know a valid block hash present in the target node's `VolatileDB` (obtainable via normal chain-sync) and send a `PerasCert` naming that block. No key material, stake, or privileged access is required. The code path is active whenever Peras certificate diffusion is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion path is enabled in production. At minimum, the implementation must verify:

1. The certificate's committee aggregate signature against the claimed voter set and round parameters.
2. That the quorum threshold is met by the signers' combined stake.
3. That the boosted block's slot falls within the correct Peras round window.

Until real validation is implemented, the object-diffusion writer for Peras certificates (`makePerasCertPoolWriterFromChainDB`) should not be wired into a live node, or an explicit guard should reject all inbound certificates at the protocol handler level.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the object-diffusion mini-protocol.
2. Observe (via chain-sync) a block hash `H` on a fork that is currently lighter than the node's selected chain.
3. Craft a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slot H }` for any round `R` not yet in the node's `PerasCertDB`.
4. Send the certificate batch to the node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
6. The certificate is forwarded to `ChainDB.addPerasCertAsync`.
7. `chainSelSync` finds block `H` in the `VolatileDB` and calls `chainSelectionForBlock` with the boosted weight.
8. If `perasWeight mkPerasParams` is large enough to overcome the honest chain's length advantage, the node switches to the attacker's fork. [5](#0-4) [6](#0-5) [7](#0-6)

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
