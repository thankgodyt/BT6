### Title
Unauthenticated Peras Vote Acceptance Enables Attacker-Controlled Chain Selection Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production-active degenerate `BlockSupportsPeras` instance's `validatePerasVote` implementation accepts any inbound Peras vote from a peer as long as the claimed voter ID appears in the stake distribution, without verifying any cryptographic signature. Because the degenerate `PerasVote blk` data type carries no signature field at all, an unprivileged peer can forge votes on behalf of any committee member, choosing any `pvVoteBlock` target. Once enough forged votes accumulate to reach quorum, a certificate is internally forged and submitted to `chainSelSync`, which re-runs chain selection with the boosted block's weight inflated — potentially causing the node to abandon its canonical chain for an attacker-chosen fork.

### Finding Description

**Root cause — missing signature field and no-op validation in the catch-all instance**

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that must authenticate an inbound vote before it enters the node's state. The catch-all instance that currently covers every block type (including Cardano blocks, because no overriding instance exists) defines the vote type without a signature field and the validator as a pure stake-distribution lookup:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  data PerasVote blk = PerasVote
    { pvVoteRound  :: PerasRoundNo
    , pvVoteBlock  :: Point blk      -- attacker-chosen target
    , pvVoteVoterId :: PerasVoterId  -- any ID in the stake distribution
    }

  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
```

There is no signature, no VRF proof, and no ownership check of any kind.

**Attacker-controlled entry path**

The ObjectDiffusion inbound handler receives `PerasVote blk` objects from any connected peer and calls `opwAddObjects`, which resolves to `processVotes` in `makePerasVotePoolWriterFromChainDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
```

`processVotes` calls `validateVote` for each received vote; if all pass, they are timestamped and forwarded to `addPerasVoteWithAsyncCertHandling`. The only rejection path is `Left PerasValidationErr`, which is only returned when the voter ID is absent from the stake distribution — a public, on-chain datum.

**Certificate forging and chain selection trigger**

Inside `implAddVote` / `updatePerasRoundVoteStates`, once accumulated stake for a target block crosses the quorum threshold, `forgePerasCert` is called (also a no-op validator in the same degenerate instance) and the resulting `ValidatedPerasCert` is enqueued via `addPerasCertAsync`. `chainSelSync` then processes it:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

`chainSelectionForBlock` re-evaluates `preferAnchoredCandidate` using `weightedSelectView`, which adds `wsvWeightBoost` (the Peras certificate boost) to the candidate's total weight. A candidate that was previously lighter than the current chain can now be preferred.

### Impact Explanation

An unprivileged peer can forge votes for any set of committee members whose IDs appear in the public stake distribution, targeting any block in the VolatileDB. By accumulating enough forged votes to reach quorum, the attacker causes the local node to:

1. Internally forge a `ValidatedPerasCert` boosting the attacker-chosen block.
2. Re-run chain selection with that block's weight artificially inflated by `perasWeight params`.
3. Potentially switch to a non-canonical fork, diverging from the honest chain.

This is a **High** severity chain-selection integrity failure: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of the Ouroboros Peras protocol.

### Likelihood Explanation

The attack requires no privileged access. Voter IDs (`PerasVoterId`, a `KeyHash` of a pool's cold key) are publicly derivable from the on-chain stake distribution, which is already read by the node at `getStakeDistrSTM`. The attacker only needs to be a connected peer and send a batch of `PerasVote` objects with valid voter IDs and a chosen `pvVoteBlock`. The number of forged votes needed equals the quorum threshold (a fraction of total stake), but since the attacker can impersonate every committee member, quorum is trivially reachable. The `PerasVoteId` uniqueness check prevents duplicate votes per voter per round, but does not prevent one forged vote per distinct voter ID.

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` in the concrete (non-degenerate) instance, mirroring the `pvSignature` field already present in `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`.
2. Implement `validatePerasVote` to verify that signature against the voter's public key retrieved from the stake distribution, analogous to `implVerifyVote` in `Ouroboros.Consensus.Committee.WFALS` and `Ouroboros.Consensus.Committee.EveryoneVotes`.
3. Until the real instance is in place, gate the ObjectDiffusion vote inbound path so that it is only active when a properly authenticated `BlockSupportsPeras` instance is available, preventing the degenerate instance from being reachable via the network.

### Proof of Concept

1. Connect to a target node as a normal peer.
2. Obtain the current `PerasVoteStakeDistr` (derivable from the public stake distribution).
3. For each `PerasVoterId` in the distribution, craft a `PerasVote` with:
   - `pvVoteRound` = current Peras round
   - `pvVoteBlock` = point of an attacker-controlled fork block already in the VolatileDB
   - `pvVoteVoterId` = the committee member's ID
4. Send the batch via the ObjectDiffusion miniprotocol.
5. `processVotes` calls `validatePerasVote`; each vote passes because the voter ID is in the stake distribution and no signature is checked.
6. `implAddVote` accumulates stake; once quorum is reached, `forgePerasCert` produces a `ValidatedPerasCert` boosting the attacker's block.
7. `addPerasCertAsync` enqueues the certificate; `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
8. `preferAnchoredCandidate` now returns `ShouldSwitch` for the attacker's fork due to the inflated `wsvWeightBoost`, and the node switches chains. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-152)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
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
