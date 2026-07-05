### Title
Missing Peras Certificate Validation Enforcement — `validatePerasCert` Unconditionally Accepts All Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass declares a `validatePerasCert` method that is called on every inbound Peras certificate received from a peer. The current production instance unconditionally returns `Right` — it accepts every certificate without checking any protocol parameter, quorum proof, or cryptographic content. An unprivileged peer can send a crafted `PerasCert` for any block, have it accepted, and cause the node to apply a weight boost to that block, potentially making the node prefer a non-canonical chain.

---

### Finding Description

`PerasParams` declares several protocol limits — `perasCertMaxRounds`, `perasQuorumStakeThreshold`, `perasQuorumStakeThresholdSafetyMargin`, etc. — that are supposed to govern whether a certificate is legitimate. [1](#0-0) 

The `BlockSupportsPeras` typeclass exposes `validatePerasCert` as the gating function for certificate acceptance: [2](#0-1) 

However, the only concrete instance — a blanket `instance StandardHash blk => BlockSupportsPeras blk` — ignores all parameters and unconditionally returns `Right`:

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
``` [3](#0-2) 

This is the exact structural analog of the Mintify bug: `MAX_SUPPLY` is declared but never checked in `mint()`; here `PerasParams` (including quorum thresholds) is declared and passed in, but `validatePerasCert` never checks any of it.

The inbound processing path in `processCerts` calls this function on every certificate received from a peer and only rejects a batch if `validateCert` returns `Left`: [4](#0-3) 

Both the `PerasCertDB`-backed and `ChainDB`-backed pool writers use `validatePerasCert mkPerasParams` as the validator: [5](#0-4) 

Once a certificate passes this non-validation, it is stored and forwarded to `addPerasCertAsync`, which enqueues it for chain selection: [6](#0-5) 

Chain selection then applies the certificate's weight boost (`vpcCertBoost = perasWeight params = 15`) to the boosted block, potentially causing the node to switch to a fork it would otherwise reject: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` claiming to boost any block — including one on a minority fork that never legitimately reached quorum. Because `validatePerasCert` accepts it unconditionally, the node applies a `perasWeight` boost (15 units) to that block. Since Peras chain selection compares total weight (block count + certificate boosts), a crafted certificate can make a shorter or weaker fork appear heavier than the honest chain, causing the node to switch to a non-canonical chain. This is a bypass of Peras certificate verification that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The object diffusion mini-protocol for Peras certificates is a public, peer-facing interface. Any connected peer can send a batch of `PerasCert` objects. No stake, key material, or privileged access is required. The attack requires only constructing a valid CBOR-encoded `PerasCert` record (two fields: `pcCertRound` and `pcCertBoostedBlock`), which is trivially serializable. [8](#0-7) 

---

### Recommendation

Implement `validatePerasCert` to enforce all protocol invariants before accepting a certificate:

1. **Quorum proof**: verify that the certificate carries a valid aggregate signature or proof that a quorum of stake (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`) voted for the boosted block in the claimed round.
2. **Certificate age**: reject certificates whose round number is more than `perasCertMaxRounds` rounds behind the current round.
3. **Boosted block existence**: verify that `pcCertBoostedBlock` refers to a known block on a plausible chain.
4. **Round consistency**: verify that `pcCertRound` is consistent with the slot of the boosted block and the `perasRoundLength`.

Until the full cryptographic validation is in place, the function should at minimum reject certificates with obviously invalid fields (e.g., a boosted block at `GenesisPoint`, or a round number that is impossibly far in the future).

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect a malicious peer to an honest node via the object diffusion mini-protocol.
2. Construct a `PerasCert` targeting a block on a minority fork `F` that has fewer blocks than the honest chain `H`:
   ```
   PerasCert { pcCertRound = <current_round>, pcCertBoostedBlock = <tip of F> }
   ```
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = 15 }` unconditionally.
4. The certificate is stored and `addPerasCertAsync` is called.
5. `chainSelSync` applies the 15-unit boost to the tip of `F`. If `|H| < |F| + 15` in weight, the node switches to `F`.
6. The honest node is now on the non-canonical fork `F`. [3](#0-2) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-131)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
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
