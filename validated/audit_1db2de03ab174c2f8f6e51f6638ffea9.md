### Title
Peras Vote Signature Verification Bypass Allows Unprivileged Peer to Forge Votes and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance used for all block types defines `PerasVote blk` without a cryptographic signature field and implements `validatePerasVote` as a stub that only checks stake-distribution membership. Any unprivileged peer can therefore forge votes attributed to any registered stake-pool voter, accumulate a quorum of such forged votes, cause the node to generate a fraudulent Peras certificate, and trigger chain selection toward an attacker-chosen chain.

### Finding Description

**Root cause — no signature field and no signature check in the degenerate instance**

The only deployed `BlockSupportsPeras` instance is the degenerate catch-all at: [1](#0-0) 

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

The `PerasVote` data type defined in this instance carries no signature: [2](#0-1) 

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId blk
  }
```

`validatePerasVote` therefore cannot perform any cryptographic check and only looks up the voter ID in the stake distribution: [3](#0-2) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

**Attacker-controlled entry path**

Inbound Peras votes arrive over the node-to-node ObjectDiffusion mini-protocol. The pool writer for votes calls `validatePerasVote` directly before storing: [4](#0-3) 

```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          (\vote -> getStakeDistrSTM >>= \sd ->
              pure $ validatePerasVote mkPerasParams sd vote)
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    ...
    }
```

`processVotes` rejects a batch only if `validatePerasVote` returns `Left`; a vote whose `pvVoteVoterId` is present in the stake distribution always returns `Right`: [5](#0-4) 

**Quorum → certificate → chain selection**

Once enough forged votes accumulate for the same `(roundNo, block)` target, `updatePerasRoundVoteStates` inside `implAddVote` generates a `ValidatedPerasCert` and returns `AddedPerasVoteAndGeneratedNewCert`: [6](#0-5) 

That certificate is immediately enqueued for asynchronous chain selection via `addPerasCertAsync`, which can cause the node to switch to the attacker's chosen chain: [7](#0-6) 

The `implAddVote` function itself also carries an explicit TODO acknowledging the missing validation: [8](#0-7) 

### Impact Explanation

An unprivileged peer can forge Peras votes attributed to any registered stake-pool voter (voter IDs are public). By sending enough forged votes for a single `(roundNo, targetBlock)` pair to exceed the quorum threshold, the peer causes the victim node to:

1. Generate a fraudulent `ValidatedPerasCert` internally.
2. Add it to the `PerasCertDB` and trigger chain selection.
3. Potentially switch to a chain boosted by the fraudulent certificate.

This is a **bypass of Peras voting authorization** — the entire purpose of the cryptographic vote-signing scheme is circumvented. The impact falls squarely within: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

- **No privilege required**: any node-to-node peer connection suffices.
- **Voter IDs are public**: the stake distribution is publicly readable from the ledger state.
- **Quorum is stake-weighted**: the attacker must forge votes for voters whose combined stake exceeds the quorum threshold, but since there is no signature to forge — only a voter ID to copy — this is trivially achievable by selecting the top stakers.
- **No cryptographic barrier**: the `PerasVote` type carries no signature field, so there is nothing to break.

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` in the production instance (analogous to the BLS-based `VoteSignature` already defined in `PerasBLSCrypto`).
2. Implement `validatePerasVote` to verify that signature against the voter's registered public key before accepting the vote.
3. Until a real Cardano-specific `BlockSupportsPeras` instance with proper signature verification is deployed, the ObjectDiffusion vote-ingest path should be disabled or gated behind a feature flag so that the degenerate stub instance cannot be exploited on a live network.

### Proof of Concept

1. Connect to a target node as a normal NTN peer.
2. Read the current stake distribution (public ledger query) to enumerate registered voter IDs and their stakes; select a set whose combined stake exceeds the Peras quorum threshold.
3. For each selected voter ID `vid`, construct `PerasVote { pvVoteRound = r, pvVoteBlock = targetBlock, pvVoteVoterId = vid }` — no signing key needed.
4. Send the batch via the ObjectDiffusion mini-protocol.
5. `processVotes` calls `validatePerasVote`; each vote passes because `lookupPerasVoteStake` finds `vid` in the distribution.
6. `addPerasVoteWithAsyncCertHandling` accumulates the votes; once quorum is reached, `AddedPerasVoteAndGeneratedNewCert cert` is returned and `addPerasCertAsync` enqueues the fraudulent certificate.
7. `chainSelSync` processes the certificate and may switch the node's preferred chain to `targetBlock`'s chain, completing the unauthorized chain-selection manipulation.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-340)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L361-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-200)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
