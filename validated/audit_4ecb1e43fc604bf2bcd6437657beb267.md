### Title
Peras Certificate Validation Bypass: Stub `validatePerasCert` Always Accepts Any Inbound Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or semantic checks. Any unprivileged peer can send a crafted `PerasCert` via the object-diffusion mini-protocol; the certificate will pass "validation," be stored in the `PerasCertDB`, and trigger chain selection with an attacker-controlled weight boost — potentially causing an honest node to prefer a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` catch-all instance in `SupportsPeras.hs` is the only instance in the codebase and is used for every block type:

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

This stub is wired directly into the inbound certificate processing path. `processCerts` in `PerasCert.hs` receives a batch of `PerasCert` objects from a remote peer, calls the supplied `validateCert` function on each one, and — if all pass — adds them to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both production pool-writer constructors pass `validatePerasCert mkPerasParams` as the validation callback: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `partitionEithers` call will always produce an empty error list, and every inbound certificate — regardless of its content — is accepted and stored.

Once stored, `chainSelSync` processes the certificate. If the certificate's `pcCertBoostedBlock` is present in the VolatileDB, `chainSelectionForBlock` is triggered for that block, applying the attacker-controlled weight boost to it: [4](#0-3) 

The checks that are entirely absent from `validatePerasCert` but are required by the Peras protocol (CIP-0140) include:
- BLS aggregate signature verification over `(roundNo, boostedBlock)`
- Committee membership and eligibility proof verification for each voter
- Quorum threshold check on the aggregate stake of the voters
- Verification that `pcCertBoostedBlock` is a real, known block hash

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An adversary connected via the object-diffusion mini-protocol can craft a `PerasCert` with:
- An arbitrary `pcCertBoostedBlock` pointing to any block in the VolatileDB (e.g., a block on a minority fork)
- Fabricated voter fields and a fake BLS signature

The certificate passes validation, is stored in the `PerasCertDB`, and its weight boost is applied during chain selection. If the boosted fork's total weight (chain length + Peras boost) exceeds the current selection's weight, the node switches to the adversarial fork. This directly violates the Peras chain-selection security property, which assumes certificates are only issued by a legitimate quorum of committee members.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol for Peras certificates is a public, peer-facing interface. Any node that connects to the victim and sends a well-formed CBOR-encoded `PerasCert` (structurally valid, but cryptographically fabricated) will have it accepted. No privileged access, key material, or stake is required. The attack is repeatable and requires only a single network connection.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that performs, at minimum:

1. **Aggregate BLS signature verification**: verify `pcSignature` over `hash(pcRoundNo || pcBoostedBlock)` using the aggregate public key derived from `pcVoters`.
2. **Committee membership check**: for each voter in `pcVoters`, verify their eligibility proof (VRF output) against the current committee selection.
3. **Quorum check**: verify that the total stake of the voters in `pcVoters` meets the quorum threshold from `PerasParams`.
4. **Boosted block existence check** (direct analog to the reported `FinalBlobNotSubmitted` fix): verify that `pcCertBoostedBlock` corresponds to a block that is actually known to the node (present in the VolatileDB or ImmutableDB) before accepting the certificate.

Until a real implementation is available, inbound certificates from untrusted peers should be rejected entirely rather than accepted unconditionally.

---

### Proof of Concept

1. Connect to a victim node via the object-diffusion mini-protocol for Peras certificates.
2. Construct a `PerasCert` with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <Point of a block on a minority fork in the victim's VolatileDB>`
   - `pcVoters = <any non-empty voter map>`
   - `pcSignature = <zeroed/random bytes>`
3. Send the certificate to the victim.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{...}` unconditionally.
5. The certificate is stored in the `PerasCertDB` and `addPerasCertAsync` is called.
6. `chainSelSync` processes the certificate; since the boosted block is in the VolatileDB, `chainSelectionForBlock` is triggered with the weight boost applied.
7. If the boosted fork's weighted length now exceeds the current selection, the victim switches to the adversarial fork. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
```haskell
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
