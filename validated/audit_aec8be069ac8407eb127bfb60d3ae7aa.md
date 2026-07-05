### Title
Peras Certificate Validation Stub Allows Unprivileged Peer to Arbitrarily Boost Any Block's Chain-Selection Weight — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural validation. An unprivileged peer can therefore send a crafted `PerasCert` that boosts an arbitrary block — including one on an adversarial fork — causing the receiving node to prefer that fork over the honest chain once the boost exceeds the honest chain's weight advantage.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must be passed before a certificate is stored and its weight boost applied to chain selection. The only concrete instance in the production codebase is the degenerate catch-all:

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

This stub is the instance used for all block types, including the Cardano block type, because no era-specific override exists yet. The function always returns `Right`, meaning every certificate — regardless of its cryptographic content, committee membership, or round validity — is treated as fully validated.

The network entry point is `processCerts`, called from both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`:

```haskell
processCerts
  systemTime
  (PerasCertDB.getCertIds perasCertDB)
  (validatePerasCert mkPerasParams)   -- always Right
  (void . join . atomically . PerasCertDB.addCert perasCertDB)
  certs
``` [2](#0-1) 

`processCerts` partitions the batch into valid/invalid using `validateCert`; since the stub always returns `Right`, the "invalid" partition is always empty and every certificate is forwarded to `addCert`. [3](#0-2) 

Once stored in `PerasCertDB`, the certificate's boost is included in `implGetWeightSnapshot`, which feeds `weightBoostOfFragment` used by `WeightedSelectView.preferCandidate` during chain selection: [4](#0-3) [5](#0-4) 

Chain selection is then triggered for the boosted block via `chainSelSync`: [6](#0-5) 

The only guard in `chainSelSync` is an age check (the boosted block must not be older than the immutable tip). There is no check on the certificate's authenticity. [7](#0-6) 

---

### Impact Explanation

**Peras certificate verification bypass enabling unauthorized chain-selection manipulation.**

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to any block in the node's VolatileDB (e.g., the tip of an adversarial fork).
2. Send it via the Peras certificate object-diffusion mini-protocol.
3. The certificate passes `validatePerasCert` unconditionally.
4. The certificate is stored; `vpcCertBoost` (drawn from `perasWeight params`) is added to the adversarial block's weight.
5. If the accumulated boost makes the adversarial fork's `wsvTotalWeight` exceed the honest chain's, `preferCandidate` returns `ShouldSwitch` and the node adopts the adversarial chain.

This is a direct bypass of the Peras voting/certificate check that enables unauthorized certificate acceptance and a resulting chain-selection error, matching both the Critical and High impact tiers.

---

### Likelihood Explanation

**High** when Peras is enabled. The attack requires only:
- A TCP connection to the target node (standard peer connection).
- Knowledge of a block hash in the node's VolatileDB (obtainable via ChainSync).
- Sending a single well-formed `PerasCert` CBOR message.

No stake, keys, or privileged access are required. The CHANGELOG confirms Peras is disabled by default, but the code path is fully wired and the vulnerability is latent in all deployments that enable Peras.

---

### Recommendation

1. **Immediate**: Gate the entire Peras certificate ingest path on a runtime check that Peras is enabled *and* that a real `validatePerasCert` implementation is present. Reject all certificates if only the stub instance is active.
2. **Short-term**: Implement `validatePerasCert` with full committee-membership and aggregate-signature verification before enabling Peras in any production deployment. The existing `EveryoneVotes` and `WFALS` committee implementations in `Ouroboros.Consensus.Committee` already demonstrate the correct verification pattern (`implVerifyCert`).
3. **Structural**: Replace the catch-all `instance StandardHash blk => BlockSupportsPeras blk` with a compile-time error or a `NoPerasSupport` sentinel that makes it impossible to accidentally use the stub in a live node.

---

### Proof of Concept

**Setup**: Node with Peras enabled, connected to an attacker peer. Honest chain tip is at block `H` (block number 100). Adversarial fork tip is at block `A` (block number 98, forking 5 blocks back).

**Attack**:
```
Attacker → Node:  PerasCert { pcCertRound = 42, pcCertBoostedBlock = Point(A) }
```

**Node processing**:
1. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })`.
2. `PerasCertDB.addCert` stores the cert; `implGetWeightSnapshot` now returns `{Point(A) → perasWeight}`.
3. `chainSelSync` sees `boostedBlock = Point(A)` is in VolatileDB; calls `chainSelectionForBlock` for `A`.
4. `weightedSelectView` computes: honest chain total weight = 100; adversarial chain total weight = 98 + `perasWeight`.
5. If `perasWeight ≥ 3` (the default `perasWeight` in `mkPerasParams`), `preferCandidate` returns `ShouldSwitch` and the node rolls back to the adversarial fork. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L41-87)
```haskell
data WeightedSelectView proto = WeightedSelectView
  { wsvBlockNo :: !BlockNo
  -- ^ The 'BlockNo' at the tip of a fragment.
  , wsvWeightBoost :: !PerasWeight
  -- ^ The weight boost of a fragment (w.r.t. a particular anchor).
  , wsvTiebreaker :: TiebreakerView proto
  -- ^ Lazy because it is only needed when 'wsvTotalWeight' is inconclusive.
  }

deriving stock instance Show (TiebreakerView proto) => Show (WeightedSelectView proto)
deriving stock instance Eq (TiebreakerView proto) => Eq (WeightedSelectView proto)

-- TODO: More type safety to prevent people from accidentally comparing
-- 'WeightedSelectView's obtained from fragments with different anchors?
-- Something ST-trick like?

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```
