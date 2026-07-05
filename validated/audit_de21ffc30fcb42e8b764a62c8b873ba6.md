### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Unauthorized Chain Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance for all block types contains a stub `validatePerasCert` that unconditionally returns `Right` (success) for every certificate, performing no cryptographic or semantic checks. When Peras is enabled, any unprivileged peer can send crafted certificates that boost arbitrary blocks, causing chain selection to assign extra weight to non-canonical forks and potentially switching the node away from the honest chain.

---

### Finding Description

**Root cause — stub validator always succeeds:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must be passed before a certificate influences chain selection. The only concrete instance in the codebase is the degenerate universal instance:

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

This stub accepts every certificate unconditionally and assigns it the full configured `perasWeight`. No signature, quorum, round-number, or committee-membership check is performed. [1](#0-0) 

**Production inbound path — `processCerts` relies entirely on this validator:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as the sole validation step for every certificate received from a peer via the object-diffusion mini-protocol:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`processCerts` then partitions results: if all certificates return `Right` (which they always do), they are timestamped and forwarded to `ChainDB.addPerasCertAsync`. If any returns `Left`, the batch is rejected. Because the stub never returns `Left`, every batch is accepted. [2](#0-1) [3](#0-2) 

**Chain selection consequence — accepted certificates alter fork preference:**

`chainSelSync` for `ChainSelAddPerasCert` adds the certificate to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block. Chain selection compares candidates using `getPerasWeightSnapshot`, which includes the weight boost from every accepted certificate. A fork whose tip block is boosted by a crafted certificate therefore appears heavier than it truly is, and the node may switch to it. [4](#0-3) 

**No secondary validation layer exists.** `implAddCert` in `PerasCertDB.Impl` performs only a duplicate-round-number check; it contains its own TODO noting that non-trivial validation logic is still missing:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [5](#0-4) 

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

When Peras is enabled, an adversary with a network connection can:

1. Identify (or craft) a block on a competing fork that is otherwise slightly less preferred than the honest chain tip.
2. Send a `PerasCert` message via the object-diffusion mini-protocol claiming to boost that block.
3. The stub validator accepts it; the certificate is stored and the boosted block's weight is increased by `perasWeight params`.
4. `chainSelectionForBlock` is triggered for the boosted block; if the boosted fork now outweighs the current selection, the node switches to it.
5. The node has adopted a non-canonical chain without any legitimate quorum of Peras committee members having voted for it.

This directly violates the Peras security invariant that only blocks certified by a genuine quorum of stake-weighted committee members receive a weight boost, and it falls squarely within the allowed impact scope: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Low-to-medium.** Peras is not enabled by default (`disableGenesisConfig` / `mkGenesisConfig Nothing` is the default path, and Peras weight is zero when disabled). However, the feature is actively being integrated and the configuration flag `gcfEnableLoEAndGDD` / Peras parameters can be set by operators. Any deployment that enables Peras is immediately exposed. The attack requires only a standard peer connection and the ability to send a well-formed (but cryptographically unverified) certificate message — no keys, no stake, no privilege. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic and semantic validation before Peras is enabled in any production deployment. At minimum, the implementation must verify:

- The aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed voters (as already implemented in `EveryoneVotes.implVerifyCert` and `WFALS.implVerifyCert`).
- That each claimed voter is a legitimate committee member with non-zero stake for the relevant epoch.
- That the total stake of the voters meets the quorum threshold (`stakeAboveThreshold`).
- That the round number is within the valid window (not too old, not from the future).

Until this is done, Peras certificate acceptance should be gated behind a feature flag that is verifiably off in all production configurations, and the `processCerts` inbound path should reject all certificates when real validation is absent.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer  ──[ObjectDiffusion PerasCert message]──►  makePerasCertPoolWriterFromChainDB
                                                  └─ processCerts
                                                       └─ validatePerasCert mkPerasParams cert
                                                            └─ always returns Right ValidatedPerasCert{..}
                                                       └─ addCert (ChainDB.addPerasCertAsync)
                                                            └─ chainSelSync (ChainSelAddPerasCert)
                                                                 └─ PerasCertDB.addCert  (stored)
                                                                 └─ chainSelectionForBlock boostedHdr
                                                                      └─ getPerasWeightSnapshot
                                                                           (boosted fork now heavier)
                                                                      └─ node switches to adversarial fork
```

**Deterministic reproduction (no mainnet required):**

1. Start a node with Peras enabled (`perasWeight > 0`).
2. Connect a peer that serves two competing forks `F_honest` and `F_adv` of equal block-number length.
3. The peer sends a `PerasCert` for the tip of `F_adv` with any round number and any (invalid) aggregate signature.
4. `validatePerasCert` returns `Right`; the certificate is stored; chain selection re-runs with `F_adv` boosted by `perasWeight`.
5. The node selects `F_adv` despite it having no legitimate quorum backing.

The stub is at: [7](#0-6) 

The inbound processing path is at: [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
```
