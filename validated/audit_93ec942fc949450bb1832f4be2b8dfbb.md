### Title
`validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Bypassing All Cryptographic and Committee Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic, committee-membership, or quorum checks. This stub is wired directly into the production inbound-certificate processing path (`processCerts` / `makePerasCertPoolWriterFromChainDB`). When Peras is enabled, any unprivileged peer can inject arbitrary `PerasCert` values — boosting any block point with any round number — and the node will accept them as fully validated, add them to the `PerasCertDB`, and trigger chain selection for the boosted block.

### Finding Description

**Root cause — stub validator always returns `Right`:**

The `BlockSupportsPeras` class defines `validatePerasCert` as a method that must verify a certificate before it is trusted. The universal instance (applied to all block types) implements it as:

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

No signature check, no committee-membership check, no quorum check, no round-number plausibility check — every certificate is immediately wrapped in `ValidatedPerasCert` and returned as `Right`.

**Production wiring — stub is called on every inbound certificate from a peer:**

`makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` argument to `processCerts`:

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

`processCerts` calls `validateCert` on every new certificate received from a peer and, if all pass, adds them to the database and triggers chain selection:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable. Every certificate from every peer is accepted.

**Chain selection consequence:**

`addPerasCertAsync chainDB` feeds the accepted certificate into `chainSelSync`, which triggers `chainSelectionForBlock` for the boosted block:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The boost weight assigned is `perasWeight mkPerasParams = PerasWeight 15`, which is the configured chain-selection weight boost per certificate. [5](#0-4) 

**Parallel issue in `validatePerasVote`:**

The same instance also omits all cryptographic signature verification from `validatePerasVote`, accepting any vote from any `PerasVoterId` present in the stake distribution without verifying the voter's private key:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [6](#0-5) 

### Impact Explanation

When Peras is enabled (via `rnFeatureFlags`), an unprivileged peer can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block in the VolatileDB and any `pcCertRound`.
2. Send it over the object-diffusion mini-protocol.
3. The receiving node accepts it unconditionally, adds it to the `PerasCertDB` with `PerasWeight 15`, and triggers chain selection for the boosted block.
4. If the boosted block is on a competing fork, the node may switch to that fork — a non-canonical chain — purely because of the injected fake certificate.

Multiple such certificates (one per round number, since the DB deduplicates by round) can be injected to accumulate weight on an adversarially chosen fork, causing the honest node to prefer a chain that no legitimate quorum ever certified. This is a **chain selection safety failure** triggered by an unprivileged peer via a crafted protocol message.

The analog to the external report is exact: just as `CultureIndex.createPiece()` stores unsanitized user-controlled strings that later override validated fields in `tokenURI`, `validatePerasCert` stores peer-controlled certificate data without any validation, and that data later overrides the honest chain-selection outcome.

### Likelihood Explanation

Any peer that can reach the object-diffusion endpoint for Peras certificates can exploit this. No stake, no keys, and no prior relationship with the node are required. The only precondition is that the node operator has enabled Peras via the experimental feature flag. The codebase explicitly marks this as a known gap (`TODO: replace when actual plumbing is in place`) with a linked issue, confirming the stub is intentional but unfinished — not a deliberate security design.

### Recommendation

1. **Do not expose `validatePerasCert` (or `validatePerasVote`) in any network-reachable path until the actual cryptographic and committee-membership checks are implemented.** Until then, the object-diffusion handlers for Peras certificates and votes should reject all inbound objects unconditionally when running with the stub instance.
2. Replace the universal stub instance with a type-class method that has no default implementation, forcing each concrete block type to provide a real validator before the code compiles.
3. Add a compile-time or runtime guard that prevents `makePerasCertPoolWriterFromChainDB` from being constructed when the validator is the stub.

### Proof of Concept

With Peras enabled, a malicious peer sends a single CBOR-encoded `PerasCert`:

```
PerasCert
  { pcCertRound    = <any round not yet in DB>
  , pcCertBoostedBlock = <Point of a block on a competing fork in the VolatileDB>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams cert`, which returns:

```haskell
Right ValidatedPerasCert
  { vpcCert = cert          -- attacker-chosen block
  , vpcCertBoost = PerasWeight 15
  }
``` [7](#0-6) 

The certificate is added to the `PerasCertDB` and `addPerasCertAsync chainDB` is called. `chainSelSync` then calls `chainSelectionForBlock` for the boosted block, potentially switching the node's selection to the attacker-chosen fork. [8](#0-7)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
