### Title
Stub `validatePerasCert` Always Accepts Peer-Supplied Peras Certificates, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing no cryptographic or committee-membership checks. Both production object-diffusion writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) call this stub against peer-supplied certificates. A successfully "validated" certificate is stored in the `PerasCertDB`, updates the `PerasWeightSnapshot`, and triggers chain selection. Because the weight boost is applied without any real validation, an unprivileged peer can craft a certificate for any block in the VolatileDB and cause the node to prefer a fork it would otherwise reject.

---

### Finding Description

**Root cause — stub validator always returns `Right`:**

In `Ouroboros.Consensus.Block.SupportsPeras`, the universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

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

No signature, committee membership, round validity, or boosted-block eligibility check is performed. Every certificate from every peer is unconditionally promoted to `ValidatedPerasCert` with a fixed weight boost of `perasWeight params` (hardcoded to `PerasWeight 15` in `mkPerasParams`). [2](#0-1) 

**Production entry path — both ChainDB and CertDB writers use the stub:**

`makePerasCertPoolWriterFromChainDB` (the production writer) passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` calls `validateCert` on every inbound certificate from a peer; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain selection consequence — accepted certificate triggers fork switch:**

`chainSelSync` processes the certificate: it adds it to the `PerasCertDB`, reads the boosted block from the VolatileDB, and calls `chainSelectionForBlock` for that block. The `PerasWeightSnapshot` (derived from all stored certificates) is then used by `compareAnchoredFragments` and `weightedSelectView` to rank candidate fragments: [5](#0-4) 

`weightedSelectView` computes `wsvWeightBoost = weightBoostOfFragment weights frag`, and `WeightedSelectView.preferCandidate` compares `wsvTotalWeight` (block number + weight boost). A fragment boosted by a fraudulent certificate gains 15 units of weight, which can flip chain selection in favour of a fork: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can send a `PerasCert` naming any block in the local VolatileDB as the boosted block. Because `validatePerasCert` never rejects any certificate, the node accepts it, stores it, and re-runs chain selection with the fraudulent weight boost applied. If the boosted block is on a fork that is otherwise equal to or slightly shorter than the current selection, the artificial +15 weight causes the node to switch to that fork. This constitutes an unauthorized Peras certificate acceptance that materially alters chain selection — a bypass of the certificate verification check that the Peras protocol requires to prevent exactly this manipulation.

---

### Likelihood Explanation

Any peer connected via the object-diffusion mini-protocol can send a `PerasCert` message. No stake, key material, or special privilege is required. The attack requires only knowledge of a block hash present in the target node's VolatileDB (obtainable via ChainSync). The vulnerability is active whenever Peras is enabled; the CHANGELOG notes Peras is currently disabled by default, but the production code path is fully wired and the feature is under active deployment.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's cryptographic aggregate signature against the claimed committee members.
2. That the signers were eligible committee members for the stated round (using the stake distribution from the ledger view, analogous to how `validatePerasVote` consults `PerasVoteStakeDistr`).
3. That the boosted block's slot satisfies `perasBlockMinSlots` and that the round number is within `perasCertMaxRounds` of the current round.

Until real validation is in place, the object-diffusion writers should refuse to accept any inbound certificate (return a hard error rather than calling the stub), or Peras must remain disabled in all deployments.

---

### Proof of Concept

1. Node A has Peras enabled. Its VolatileDB contains block `B` on a fork that is 14 blocks shorter than the current selection (so `blockNo(B) + 14 < blockNo(tip)`).
2. Attacker peer sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = point(B) }` over the object-diffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`. No error is raised.
4. `addPerasCertAsync` stores the certificate; `chainSelSync` calls `chainSelectionForBlock` for `B`.
5. `weightedSelectView` computes `wsvTotalWeight = blockNo(B) + 15`, which now exceeds `blockNo(tip)`.
6. `preferCandidate` returns `ShouldSwitch`, and the node rolls back to the fork ending at `B`. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
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
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L61-89)
```haskell
  Ordering
compareHeadBlockNo = compare `on` AF.headBlockNo

-- | Check that we can switch from @ours@ to @theirs@ by rolling back our chain
-- by at most @k@ weight.
--
-- If @ours@ and @cand@ do not intersect, this returns 'False'. If they do
-- intersect, then we check that the suffix of @ours@ after the intersection has
-- total weight at most @k@.
forksAtMostKWeight ::
  ( StandardHash blk
  , HasHeader b
  , HeaderHash blk ~ HeaderHash b
  ) =>
  PerasWeightSnapshot blk ->
  -- | By how much weight can we roll back our chain at most?
  PerasWeight ->
  -- | Our chain @ours@.
  AnchoredFragment b ->
  -- | Their chain @theirs@.
  AnchoredFragment b ->
  -- | Indicates whether their chain forks at most the given the amount of
  -- weight. Returns 'False' if the two fragments do not intersect.
  Bool
forksAtMostKWeight weights maxWeight ours theirs =
  case ours `AF.intersect` theirs of
    Nothing -> False
    Just (_, _, ourSuffix, _) ->
      totalWeightOfFragment weights ourSuffix <= maxWeight
```
