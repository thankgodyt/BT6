### Title
Incomplete Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Fraudulent Chain-Selection Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a deliberately incomplete, stub implementation of `validatePerasCert` that unconditionally returns `Right` for every certificate it receives. Because this function is the sole gate between an inbound peer-supplied Peras certificate and the `ChainDB`'s chain-selection logic, any unprivileged peer can inject an arbitrary, cryptographically unsigned certificate that will be accepted, stored, and used to boost a chosen block's chain weight, potentially causing an honest node to switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory validation entry-point for Peras certificates received from peers. The universal instance that covers all block types is explicitly marked as a temporary "degenerate instance … to get things to compile":

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

The function body is a single unconditional `Right` — no signature check, no committee membership check, no round-number bounds check, no boosted-block eligibility check. Every certificate, regardless of content or origin, is promoted to a `ValidatedPerasCert` and assigned the full `perasWeight` boost.

This stub is wired directly into the production inbound-certificate pipeline. `makePerasCertPoolWriterFromChainDB` — the writer used for live peer traffic — passes `validatePerasCert mkPerasParams` as the validation callback, with a TODO acknowledging the placeholder:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`mkPerasParams` itself is a hardcoded bundle of tentative default values explicitly described as "waiting for a final decision":

```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision ...
``` [3](#0-2) 

`processCerts` — the function that drives inbound certificate handling — calls the validator and, if all certificates pass (which they always do), forwards each one to `ChainDB.addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` feeds into `chainSelSync`, which calls `chainSelectionForBlock` for the boosted block, potentially switching the node's preferred chain: [5](#0-4) 

A second incomplete stub compounds the issue: `getPerasCertInBlock _ = Nothing` means certificates embedded in received blocks are never extracted, so the on-chain certificate record used by voting and inclusion rules is always empty, further distorting the Peras state machine: [6](#0-5) 

---

### Impact Explanation

**High.** An unprivileged peer that can send Peras certificate objects (via the ObjectDiffusion mini-protocol) can craft a certificate naming any block hash and any round number. Because `validatePerasCert` never rejects anything, the certificate is stored and triggers chain selection. The boosted block gains `perasWeight` (currently hardcoded to 15) additional chain weight. If the attacker's chosen block is on a fork, the honest node may switch to that fork, diverging from the canonical chain. This satisfies the "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" impact criterion.

---

### Likelihood Explanation

**Low-to-Medium.** The Peras ObjectDiffusion mini-protocol is present in the production codebase and is wired to the ChainDB. Any peer that can establish a connection and speak the protocol can send certificates. The stub is explicitly acknowledged as incomplete and is expected to be replaced before mainnet Peras activation, but the code is live in the repository and would be reachable on any testnet or pre-production deployment that enables Peras.

---

### Recommendation

1. Replace the degenerate `validatePerasCert` stub with a real implementation that verifies: committee membership of the certificate issuer, cryptographic signature over the certificate body, round-number bounds relative to the current ledger state, and boosted-block eligibility (age, slot, era).
2. Replace the degenerate `getPerasCertInBlock _ = Nothing` stub with actual HFC plumbing to extract certificates from blocks, so the on-chain certificate view used by voting and inclusion rules is accurate.
3. Replace the hardcoded `mkPerasParams` placeholder with parameters derived from the node's actual ledger configuration, not a compile-time constant.
4. Until all three stubs are replaced, gate the ObjectDiffusion Peras certificate inbound path behind a feature flag that is disabled by default on any network where Peras is not yet fully specified and audited.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node and establishes an ObjectDiffusion session for Peras certificates.
2. Attacker sends a `PerasCert` message with `pcCertRound = R` and `pcCertBoostedBlock = <hash of attacker's fork tip>`.
3. `processCerts` in `PerasCert.hs` (line 164) calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` (line 353–358 of `SupportsPeras.hs`) returns `Right ValidatedPerasCert{vpcCertBoost = 15}` unconditionally — no signature, no committee check.
5. The validated certificate is passed to `ChainDB.addPerasCertAsync`.
6. `chainSelSync` (line 483 of `ChainSel.hs`) adds the certificate to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
7. The boosted block's chain now has 15 additional weight units; if this exceeds the honest tip's weight, the node switches forks. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-145)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
