### Title
Stub `validatePerasCert` unconditionally accepts all peer-supplied Peras certificates, enabling chain-weight manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` class ships a universal degenerate instance in which `validatePerasCert` always returns `Right` — accepting every certificate without any cryptographic check. When Peras is enabled, any unprivileged peer can submit crafted certificates that pass this stub, artificially boosting the Peras weight of blocks on adversarial forks and triggering chain selection to switch away from the canonical chain.

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the gate that must verify a `PerasCert` before it can influence chain selection. The only instance in the codebase is a universal stub:

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

This stub is the instance used by the production inbound-certificate pipeline. `makePerasCertPoolWriterFromChainDB` explicitly passes it as the validator:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` — the function that handles batches of inbound certificates from peers — calls this validator on every certificate received: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate passes. The certificate is then forwarded to `addPerasCertAsync` on the `ChainDB`: [2](#0-1) 

Inside `chainSelSync`, the certificate's boosted block is looked up in the `VolatileDB` and, if present, chain selection is immediately re-run for it: [4](#0-3) 

Chain selection compares fragments using `weightedSelectView`, which adds `wsvWeightBoost` (the Peras boost from the certificate) to the block number when comparing candidates: [5](#0-4) 

The boost value is `perasWeight params` — a fixed protocol parameter, not attacker-controlled — but the attacker controls *which block* is boosted and *which round number* is claimed. Since one certificate per round is accepted (duplicates are silently dropped), an attacker can submit one fake certificate per Peras round, each targeting a different block on an adversarial fork.

The analog to the Derby slippage-tolerance bug is exact: just as any caller could invoke `rebalanceXChain()` with an arbitrary `_slippage` value that bypassed the intended tolerance bounds, any peer here can invoke the certificate-ingestion path with an arbitrary `PerasCert` that bypasses the intended cryptographic validation, because the validation function is a no-op stub.

### Impact Explanation

When Peras is enabled, an adversarial peer can:

1. Observe a valid block on a competing fork that exists in the target node's `VolatileDB` (visible because the peer is already connected).
2. Craft a `PerasCert` naming that block and a fresh `PerasRoundNo` not yet in the `PerasCertDB`.
3. Submit it via the `ObjectDiffusion` miniprotocol.
4. `validatePerasCert` returns `Right` unconditionally; the certificate is stored.
5. Chain selection re-runs for the boosted block. If `blockNo(fork_tip) + perasWeight > blockNo(current_tip)`, the node switches to the adversarial fork.

This is a **chain-selection error** matching the "High" tier: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of Ouroboros Peras.

The rollback is bounded by the immutable-tip check (`pointSlot boostedBlock < AF.anchorToSlotNo immTip` causes early exit), so the maximum divergence is `k` blocks — still a severe consensus safety violation.

### Likelihood Explanation

- **Precondition**: Peras must be enabled. It is currently disabled by default, but the code path is fully wired and the `ObjectDiffusion` miniprotocol for certificates is present in production files.
- **Attacker capability**: Any connected peer; no keys, no stake, no special role required.
- **Knowledge required**: A valid block hash in the target's `VolatileDB` — trivially observable by any peer that has been syncing with the node.
- **Effort**: Sending a single well-formed CBOR-encoded `PerasCert` message. The `PerasCert` type has only two fields (`pcCertRound`, `pcCertBoostedBlock`) and is fully serialisable.

### Recommendation

1. **Do not enable Peras in production until `validatePerasCert` performs real cryptographic validation** (signature verification, committee membership check, round-number range check).
2. Replace the degenerate universal instance with a proper per-era instance that implements the full Peras certificate validation rules referenced in issue `cardano-peras#120`.
3. Add a compile-time or runtime guard that prevents the `ObjectDiffusion` certificate miniprotocol from being activated unless a non-stub `validatePerasCert` is in place.
4. Similarly audit `validatePerasVote`, which only checks stake-distribution membership but does not verify the vote's cryptographic signature.

### Proof of Concept

```
Setup: private testnet with Peras enabled (PerasParams configured).

1. Attacker node A connects to honest node H as a normal peer.
2. A observes that H has received block B (hash=0xDEAD, slot=100) on a fork
   (visible via the ChainSync candidate fragment).
3. A constructs:
     PerasCert { pcCertRound = PerasRoundNo 42        -- fresh round
               , pcCertBoostedBlock = BlockPoint 100 0xDEAD }
4. A sends this certificate to H via the ObjectDiffusion miniprotocol.
5. H calls processCerts → validatePerasCert mkPerasParams cert
   → Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
6. H stores the certificate in PerasCertDB.
7. H calls chainSelectionForBlock for block 0xDEAD.
8. weightedSelectView computes:
     fork weight  = blockNo(0xDEAD) + perasWeight
     canon weight = blockNo(current_tip)
   If fork weight > canon weight, H switches to the fork.
9. H is now on the adversarial fork.
``` [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-88)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT

```
