### Title
Peras Certificate Validation Permanently Bypassed via Unconditional `Right` Stub — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a production stub for `validatePerasCert` that unconditionally returns `Right` — accepting every inbound Peras certificate without any cryptographic or semantic check. This is the sole validation gate in the inbound certificate pipeline (`processCerts`). An unprivileged peer can therefore inject crafted certificates that boost any block's Peras weight, causing an honest node to prefer a non-canonical chain during chain selection.

---

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the mandatory gatekeeper before a certificate may enter the `PerasCertDB` and influence chain selection. The universal instance — which covers all block types including Cardano — implements this method as a stub:

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

This stub is wired directly into the production inbound-certificate pipeline. `makePerasCertPoolWriterFromChainDB` passes it as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

Inside `processCerts`, the only gate is this `validateCert` call. Because it always returns `Right`, every certificate in every inbound batch is accepted:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Once accepted, the certificate is stored in `PerasCertDB` and `chainSelSync` immediately triggers `chainSelectionForBlock` for the boosted block:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection compares candidates using `WeightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost`. A crafted certificate can therefore make a shorter adversarial chain appear heavier than the honest chain:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

The analogy to the external report is direct: just as `renounceOwnership()` permanently strips the Owner role so that privileged contract functions become permanently uncallable, the stub `validatePerasCert` permanently strips the certificate-validation role so that the node can never reject an invalid Peras certificate — the gatekeeper has irrevocably renounced its authority.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An adversary with any amount of stake can produce a valid but shorter chain, then inject a crafted `PerasCert` whose `pcCertBoostedBlock` points to a block on that chain. Because `validatePerasCert` never rejects anything, the certificate is accepted, the adversarial chain gains an unbounded weight boost, and `chainSelectionForBlock` may cause the honest node to switch away from the canonical chain. No cryptographic material, no stake majority, and no operator action is required — only the ability to send a well-formed CBOR-encoded `PerasCert` over the Peras object-diffusion mini-protocol.

---

### Likelihood Explanation

**Low for current mainnet** (Peras is disabled by default per the CHANGELOG: *"if Peras is disabled (which is the default), there is no observable difference"*), but **High for any deployment where Peras is enabled** (private testnets, future mainnet activation). The attack requires only a peer connection and the ability to craft a `PerasCert` struct — no special privileges. [6](#0-5) 

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that verifies:
1. The certificate's cryptographic signature against the known committee public keys.
2. That the boosted block's slot falls within the valid Peras round window.
3. That the certificate round number is consistent with the current protocol state.

Until real validation is in place, the `TODO` at `SupportsPeras.hs:350` and `PerasCert.hs:125` should be treated as a security-critical blocker before Peras is enabled on any network.

---

### Proof of Concept

1. Stand up a private testnet with Peras enabled.
2. Connect a malicious peer to an honest node via the Peras object-diffusion mini-protocol.
3. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a shorter but valid adversarial fork.
4. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right` → certificate stored in `PerasCertDB`.
5. `chainSelSync` fires `chainSelectionForBlock` for the boosted block; `WeightedSelectView` now ranks the adversarial fork higher than the honest chain.
6. The honest node switches to the adversarial fork, diverging from the canonical chain without any rollback exceeding `k`. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/CHANGELOG.md (L95-97)
```markdown
- Changed `SelectView` to be a data type instead of an associated type of
  `ConsensusProtocol`, which is the combination of a `BlockNo` and a
  `TiebreakerView`, which is a new associated type of `ConsensusProtocol`. This
```
