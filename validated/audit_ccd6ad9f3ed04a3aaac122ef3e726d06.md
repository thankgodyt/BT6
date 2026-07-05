### Title
Unconditional Peras Certificate Acceptance Allows Unprivileged Peer to Manipulate Chain Selection Weight - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. This function is wired directly into the production peer-facing certificate ingestion path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted block; the node accepts it as a `ValidatedPerasCert`, stores it in the `PerasCertDB`, and immediately re-runs chain selection with the injected weight boost applied, potentially causing the node to prefer a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The catch-all `BlockSupportsPeras` instance (lines 320–389 of `SupportsPeras.hs`) is explicitly labelled a placeholder:

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

Every certificate, regardless of content, is wrapped in `Right` and assigned the full `perasWeight params` boost (default: `PerasWeight 15`). No signature, quorum, committee membership, round validity, or boosted-block existence check is performed.

**Production ingestion path — `makePerasCertPoolWriterFromChainDB`:**

The production writer for peer-received certificates passes this stub directly as the validator:

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

`processCerts` calls `validateCert` on each inbound certificate; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection side-effect — `chainSelSync`:**

`ChainDB.addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes it: the certificate is added to `PerasCertDB`, and chain selection is immediately re-triggered for the attacker-specified `boostedBlock`: [4](#0-3) 

**Weight boost applied during chain comparison:**

`weightedSelectView` computes `wsvWeightBoost` via `weightBoostOfFragment`, which sums all `PerasWeight` entries for points on the fragment from the `PerasWeightSnapshot`. The injected certificate's boost is included in this sum, inflating the total weight of any candidate chain containing the attacker-named block: [5](#0-4) 

`preferCandidate` then compares `wsvTotalWeight` values; a candidate with a fake boost of 15 can be preferred over the honest chain even if it is 15 blocks shorter: [6](#0-5) 

**Attacker-controlled entry point:**

The `PerasCert blk` type in the degenerate instance carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`: [7](#0-6) 

Both fields are fully attacker-controlled over the wire. The only existing guard is a staleness check (`pointSlot boostedBlock < AF.anchorToSlotNo immTip`), which is bypassed by naming any recent block.

### Impact Explanation

When Peras is enabled, an unprivileged peer can inject one `PerasCert` per round (the `PerasCertDB` deduplicates by `PerasRoundNo`) naming any block on a minority fork as the boosted block. With a default boost of 15 and a block production rate of ~1 block per 20 seconds, a single fake certificate makes a fork up to 5 minutes shorter appear heavier than the honest chain. This is a **High** severity chain selection bug: an honest node is made to prefer a non-canonical chain beyond the intended security assumptions of Ouroboros Praos/Peras, without the attacker needing any stake, keys, or operator access.

### Likelihood Explanation

The vulnerability is reachable from any peer connected via the object diffusion mini-protocol whenever Peras is enabled. No special privileges, stake, or cryptographic material are required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` with a chosen `pcCertBoostedBlock`. The `TODO replace when actual plumbing is in place` comment confirms the stub is present in the current production codebase and not gated behind a feature flag at the validation layer.

### Recommendation

Replace the stub `validatePerasCert` in the degenerate `BlockSupportsPeras` instance with a function that either:
1. Rejects all certificates outright (returning `Left PerasValidationErr`) until real validation is implemented, so no peer-supplied certificate can influence chain selection; or
2. Implements full cryptographic and semantic validation: verify the aggregate BLS signature against the claimed voter set, confirm quorum stake threshold is met using the current stake distribution, check that the boosted block's slot falls within the valid round window, and verify each voter's committee eligibility.

Until (2) is complete, option (1) is the safe default. The `makePerasCertPoolWriterFromChainDB` `TODO` comment should be resolved at the same time.

### Proof of Concept

On a private testnet with Peras enabled, an attacker peer sends the following over the object diffusion mini-protocol:

```
PerasCert
  { pcCertRound    = <current round>
  , pcCertBoostedBlock = BlockPoint <slot> <hash of attacker's minority-fork block>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams cert`, which returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }
```

The cert is stored in `PerasCertDB`. `chainSelSync` triggers chain selection for the named block. `weightedSelectView` computes `wsvTotalWeight = blockNo + 15` for any fragment containing that block. `preferCandidate` switches to the attacker's fork if its boosted total weight exceeds the honest chain's block number, causing the honest node to roll back up to 15 blocks and adopt the attacker's chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L104-112)
```haskell
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
```
