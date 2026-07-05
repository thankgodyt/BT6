### Title
Peras Certificate Validation Unconditionally Returns `Right`, Bypassing All Certificate Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing no cryptographic or structural validation whatsoever. Because this catch-all instance applies to all block types (including production Cardano blocks, for which no overriding instance exists yet), any unprivileged peer can inject an arbitrary `PerasCert` over the network that will pass "validation," be stored in the `PerasCertDB`, and trigger chain selection with an illegitimate weight boost.

---

### Finding Description

In `Ouroboros.Consensus.Block.SupportsPeras`, the overlapping-instance catch-all for `BlockSupportsPeras` provides the following implementation of `validatePerasCert`:

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

This is the **only** instance in the repository (the comment on line 318 reads `-- TODO: degenerate instance for all blks to get things to compile`), meaning it is the instance resolved for production Cardano block types.

The function is called directly in the network-facing certificate ingestion path. In `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert`, `makePerasCertPoolWriterFromChainDB` wires it as the validator:

```haskell
(validatePerasCert mkPerasParams)
```

`processCerts` then calls this validator on every inbound certificate received from a peer:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertInboundException errs)
```

Because `validatePerasCert` always returns `Right`, the `errs` branch is never taken. Every certificate, regardless of its content, is accepted and forwarded to `ChainDB.addPerasCertAsync`, which enqueues it for `chainSelSync`. There, the certificate's boosted block triggers a full chain-selection run:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

Chain selection uses `WeightedSelectView`, which compares `wsvTotalWeight` (block number + Peras weight boost). A fraudulent certificate can therefore make a non-canonical fork appear heavier than the honest chain, causing the node to switch to it.

The analogous vulnerability in the external report is the unset `_mintHook` that defaults to null, allowing anyone to bypass the intended access control. Here, the unimplemented `validatePerasCert` defaults to always-`Right`, allowing any peer to bypass Peras certificate authorization.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` (any block point in the VolatileDB). The certificate passes "validation" unconditionally, is stored in the `PerasCertDB`, and its boost is reflected in the `PerasWeightSnapshot`. Chain selection then computes `wsvTotalWeight = blockNo + weightBoost` for candidate fragments. A peer that injects a certificate boosting a block on a minority fork can make that fork's total weight exceed the honest chain's weight, causing the node to switch to the non-canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions, and can bypass Peras certificate/vote authorization entirely.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is wired into the production diffusion layer. Any connected peer can send `PerasCert` messages. No stake, key material, or special privilege is required. The attack requires only knowledge of a block hash present in the target node's VolatileDB (obtainable via normal ChainSync). Likelihood is **High** once Peras diffusion is active on a network.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate vote signature against the committee's public keys.
2. That the votes in the certificate reach the quorum threshold.
3. That the certificate's round number is within the valid window.
4. That the boosted block point is consistent with the certificate's claimed round.

Until a real implementation is available, the stub should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), mirroring the recommendation in the external report to use a default hook that always reverts rather than one that always passes.

---

### Proof of Concept

**Entry path (network → chain selection):**

1. Peer sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = someMinorityForkBlock }` via the Peras certificate object-diffusion mini-protocol.

2. `makePerasCertPoolWriterFromChainDB` receives it and calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. [1](#0-0) 

3. `validatePerasCert` unconditionally returns `Right`, so the certificate is accepted. [2](#0-1) 

4. `processCerts` adds the certificate to the ChainDB via `addCert`. [3](#0-2) 

5. `chainSelSync` processes the certificate: it looks up the boosted block in the VolatileDB and triggers `chainSelectionForBlock` for it. [4](#0-3) 

6. Chain selection computes `wsvTotalWeight = blockNo + weightBoost` using the fraudulent certificate's boost, potentially preferring the minority fork. [5](#0-4) 

**Root cause (always-`Right` validator, no specific instance for Cardano blocks):** [6](#0-5)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-180)
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
