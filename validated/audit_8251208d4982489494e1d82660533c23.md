### Title
Missing Cryptographic Validation in `validatePerasCert` Degenerate Instance Allows Unauthorized Certificate Acceptance and Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every inbound Peras certificate, performing zero cryptographic or semantic checks. This instance is wired directly into the production certificate pool writers that process certificates received from untrusted peers. Any unprivileged peer can therefore inject an arbitrary Peras certificate that boosts any block in the VolatileDB, triggering chain selection and potentially causing the node to switch to a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for all inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance — which applies to **all** block types including production Cardano blocks — implements this as:

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

This implementation skips every check that a real certificate validator must perform: aggregate BLS signature verification, round-number consistency, boosted-block hash validity, quorum membership, and voter eligibility. The result is that the `Either` branch is always `Right`, so the certificate is always treated as valid.

This stub is not confined to tests. It is the instance resolved at the two production pool-writer call sites:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams)

-- makePerasCertPoolWriterFromChainDB
(validatePerasCert mkPerasParams)
``` [2](#0-1) [3](#0-2) 

Both writers feed into `processCerts`, which calls `validateCert` on each peer-supplied certificate and, on success, adds it to the database: [4](#0-3) 

A certificate added via `makePerasCertPoolWriterFromChainDB` is forwarded to `ChainDB.addPerasCertAsync`, which invokes `chainSelSync` → `chainSelectionForBlock` for the boosted block: [5](#0-4) 

A secondary missing check exists in `validatePerasVote`: it only verifies that the voter has stake in the distribution but never verifies the cryptographic vote signature, allowing any staked identity to cast votes for arbitrary blocks without possessing the corresponding private key. [6](#0-5) 

---

### Impact Explanation

Peras certificates assign a weight boost (`perasWeight`) to a specific block. Chain selection compares candidate fragments by accumulated weight; a boosted block on a competing fork can make that fork heavier than the current selection, causing the node to roll back and switch chains. Because `validatePerasCert` never rejects any certificate, an attacker can:

1. Craft a `PerasCert` naming any block hash present in the target node's VolatileDB.
2. Send it over the Peras certificate mini-protocol.
3. The node accepts it unconditionally, adds it to the `PerasCertDB`, and triggers chain selection for the boosted block.
4. If the boosted block is on a competing fork, the node switches to that fork — a chain selection manipulation that violates the intended Peras security assumptions.

This matches the **High** impact category: a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The attack requires only that the adversary can open a connection to the target node and send a well-formed CBOR-encoded `PerasCert` message. No keys, stake, or privileged access are needed. The degenerate instance is the only resolved instance for all current block types; there is no override for Cardano blocks. The production pool writers are active whenever the Peras object-diffusion mini-protocol is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregated public keys of the claimed voters.
2. Checks that each claimed voter seat index is within bounds and maps to a registered pool with non-zero stake.
3. Validates that the certificate's round number is consistent with the current chain state.
4. Rejects certificates whose boosted block hash does not correspond to a known, header-validated block.

Until a proper implementation is available, the production pool writers should not call `validatePerasCert` with the degenerate instance, or the Peras certificate mini-protocol should remain disabled in production builds.

Similarly, `validatePerasVote` must be extended to verify the cryptographic vote signature before accepting a vote as valid.

---

### Proof of Concept

An unprivileged peer connects to the node and sends a single `PerasCert` message:

```
PerasCert
  { pcCertRound    = <any round number>
  , pcCertBoostedBlock = <hash of a block on a competing fork in the node's VolatileDB>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams cert`, which returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }
```

The certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`. `chainSelSync` looks up the boosted block header in the VolatileDB (succeeds, since the attacker chose a known hash), then calls `chainSelectionForBlock` for that header. If the fork carrying the boosted block now has greater accumulated weight than the current selection, the node rolls back and adopts the adversary-chosen fork — without the attacker ever possessing any cryptographic key or stake.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L100-106)
```haskell
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
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
