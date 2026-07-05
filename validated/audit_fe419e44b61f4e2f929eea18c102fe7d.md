### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Unprivileged Chain-Selection Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` catch-all instance ships a `validatePerasCert` implementation that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic verification. Because this function is wired directly into the live Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB` → `processCerts`), any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary block, causing the receiving node to prefer a non-canonical chain in chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate a Peras certificate before it is stored and used to influence chain selection. The repository contains a single catch-all instance for all `StandardHash blk` types, explicitly marked as a temporary scaffold:

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

This stub accepts every certificate unconditionally — no BLS aggregate signature check, no VRF eligibility proof check, no committee membership check, no round-number plausibility check.

The same instance's `validatePerasVote` only checks whether the voter ID appears in the stake distribution; the `PerasVote` data type in this instance carries **no signature field at all**, so there is nothing to verify cryptographically: [2](#0-1) 

This stub is wired into the live production ingest path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`: [3](#0-2) 

`processCerts` calls the validator on every inbound certificate and, if all pass (which they always do), adds them to the database and triggers chain selection: [4](#0-3) 

Once a certificate is stored, `chainSelSync` uses it to boost the target block's weight in chain selection: [5](#0-4) 

The `PerasCertDB.implAddCert` also carries a `TODO` noting that non-trivial validation logic is still missing: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as `pcCertBoostedBlock`. After passing the no-op `validatePerasCert`, the certificate is stored and triggers `chainSelectionForBlock` for the boosted block. Chain selection now compares candidates using Peras weight (`vpcCertBoost = perasWeight params`), so the fraudulently boosted fork can be preferred over the honest canonical chain. This is a **High** chain-selection bug: an unprivileged peer can make an honest node permanently prefer a non-canonical or adversarially-chosen chain, violating the Peras security assumption that only legitimately elected committee members can boost blocks.

---

### Likelihood Explanation

The Peras certificate mini-protocol is a public network-facing endpoint. Any connected peer can send a `PerasCert` message. No stake, no key material, and no prior relationship is required. The only guard — `validatePerasCert` — is a stub that always succeeds. Likelihood is **High** for any node running with Peras enabled.

---

### Recommendation

Replace the stub `validatePerasCert` (and `validatePerasVote`) implementations with full cryptographic verification before enabling Peras in production:

1. `validatePerasCert` must verify the BLS aggregate signature over `(pcRoundNo, pcBoostedBlock)` against the aggregate public key of the declared voters, verify each voter's committee eligibility (persistent membership or VRF-based local sortition), and confirm the declared voter set reaches quorum. The concrete BLS machinery already exists in `Ouroboros.Consensus.Peras.Crypto.BLS` and `Ouroboros.Consensus.Committee.EveryoneVotes` / `WFALS`.
2. `validatePerasVote` must verify the BLS signature in `pvSignature` against the voter's registered public key.
3. Until these checks are implemented, the Peras certificate and vote ingest paths must be disabled or gated behind a feature flag that is off by default, preventing any peer from injecting fraudulent weight boosts.

---

### Proof of Concept

1. Connect to a node with Peras enabled.
2. Craft a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <hash of any block on a minority fork>`.
3. Send the certificate over the Peras certificate mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
5. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` is called.
6. `chainSelSync` runs `chainSelectionForBlock` for the boosted block; the minority fork now carries `perasWeight params` additional weight.
7. If the boosted fork's weighted length exceeds the current selection, the node switches to the adversary's chain — without the adversary owning any committee BLS key. [7](#0-6) [3](#0-2) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
```
