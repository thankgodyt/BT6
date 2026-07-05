### Title
Peras Vote Round Number Never Validated Against Current Slot — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`)

---

### Summary

The `processVotes` function, which handles inbound Peras votes received from unprivileged peers via the ObjectDiffusion mini-protocol, delegates all validation to `validatePerasVote`. That function — in the only deployed instance — checks only whether the voter ID appears in the stake distribution. It never validates the vote's `pvVoteRound` against the current slot or round, and performs no cryptographic signature check. A malicious peer can therefore inject votes for any past (or future) round, targeting any block, claiming to be any voter in the stake distribution. If enough such votes accumulate to reach quorum, a Peras certificate is forged and submitted to chain selection, potentially causing the node to switch to a non-canonical fork.

---

### Finding Description

**Entry path — ObjectDiffusion → `processVotes`**

Inbound Peras votes from a peer are handled by `makePerasVotePoolWriterFromChainDB`, which calls `processVotes` with the following validation callback:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [1](#0-0) 

Inside `processVotes`, the only gate before a vote is accepted and timestamped with the current wall-clock time is the result of that callback: [2](#0-1) 

**The degenerate `validatePerasVote` instance**

The `BlockSupportsPeras` instance used in production is explicitly marked as a stub ("degenerate instance for all blks to get things to compile"). Its `validatePerasVote` implementation checks only whether the voter ID is present in the stake distribution: [3](#0-2) 

The function ignores `_params` entirely and performs no check on:
- `pvVoteRound` vs. the current round or slot
- `pvVoteBlock` vs. any valid chain tip
- Any cryptographic signature over the vote body [4](#0-3) 

**Voting rules are only for local vote production, not inbound validation**

The Peras voting rules (VR-1A, VR-1B, VR-2A, VR-2B) that govern which round a node may vote in are implemented in `Peras/Voting/Rules.hs` and evaluated via `PerasVotingView`. These rules are consulted only when the local node decides whether to *cast* its own vote; they are never applied to *incoming* votes from peers. [5](#0-4) 

**Arrival time is stamped with the current wall clock, not the vote's round time**

When a vote passes the (trivial) validation, it is wrapped with `WithArrivalTime now` where `now` is the current wall-clock time at the moment of receipt, not the onset of `pvVoteRound`. This means VR-1A's `lcsArrivalSlot` check — which verifies that a certificate was received within X slots of its round start — will be evaluated against the wrong time for any vote injected for a past round. [6](#0-5) 

**Certificate forging and chain selection**

Once enough votes accumulate for a `(round, block)` target, `implAddVote` in `PerasVoteDB.Impl` calls `updatePerasRoundVoteStates`, which forges a certificate and returns `AddedPerasVoteAndGeneratedNewCert`. This certificate is then submitted asynchronously to chain selection via `addPerasCertAsync`: [7](#0-6) 

Chain selection then triggers `chainSelectionForBlock` for the boosted block. If that block is on a competing fork, the node may switch to it: [8](#0-7) 

---

### Impact Explanation

A malicious peer can craft a batch of Peras votes claiming to be from multiple distinct voter IDs that are present in the stake distribution, all targeting the same `(pvVoteRound, pvVoteBlock)` pair for a block on a minority fork. Because `validatePerasVote` checks only voter-ID membership and not any cryptographic proof, round currency, or block validity, these votes pass validation. If the combined stake of the claimed voters exceeds the quorum threshold, a certificate is forged for that block, and chain selection is triggered. The Peras weight boost assigned to the boosted block can cause the node to prefer the minority fork over the canonical chain, constituting a chain-selection safety failure driven entirely by an unprivileged peer.

This maps to: **Critical — Bypass of Peras voting/certificate checks that enables unauthorized vote and certificate acceptance**, and **High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The attack requires only that the adversary know which voter IDs are in the current stake distribution (this is public on-chain data) and be able to connect to the target node as a peer. No key material, stake ownership, or operator privilege is needed. The `validatePerasVote` stub performs no signature verification, so the adversary does not need to compromise any key. The ObjectDiffusion mini-protocol is reachable from any peer. Likelihood is **High** once Peras is active on a network using this code path.

---

### Recommendation

1. **Validate `pvVoteRound` against the current round**: `processVotes` (or the `validateVote` callback) must reject votes whose round number does not correspond to the current or immediately preceding round, analogous to the timestamp margin check recommended in the original report.

2. **Verify cryptographic eligibility proofs**: `validatePerasVote` must verify the vote's eligibility proof (VRF output for non-persistent committee members, BLS signature) before accepting the vote. The `PerasVote.V1` type already carries `pvEligibilityProof` and `pvSignature` fields for this purpose.

3. **Apply Peras voting rules to inbound votes**: Inbound votes should be checked against the same VR-1/VR-2 rules that govern local vote production, using the node's current ledger view.

4. **Replace the degenerate `BlockSupportsPeras` instance**: The stub instance (tracked in `cardano-peras#73` and `#120`) must be replaced with a concrete Cardano-specific instance before Peras is deployed to any network where peers are untrusted.

---

### Proof of Concept

On a private testnet with Peras enabled and using the current code:

1. Connect to a target node as an unprivileged peer via the ObjectDiffusion mini-protocol.
2. Obtain the current `PerasVoteStakeDistr` (public on-chain data); enumerate voter IDs with non-zero stake.
3. Craft a batch of `PerasVote` objects, each with:
   - `pvVoteRound` set to any past round (e.g., round 0)
   - `pvVoteBlock` set to the point of a block on a minority fork
   - `pvVoteVoterId` set to a distinct voter ID from the stake distribution
   - `pvVoteVoterId` fields chosen so that their combined stake exceeds the quorum threshold
4. Send the batch via `opwAddObjects` of the ObjectDiffusion writer.
5. `processVotes` calls `validatePerasVote` for each vote; each passes because the voter IDs are in the distribution.
6. `implAddVote` accumulates the votes; once quorum is reached, `AddedPerasVoteAndGeneratedNewCert` is returned and a certificate is forged for the minority-fork block.
7. `addPerasCertAsync` submits the certificate to chain selection; `chainSelectionForBlock` is triggered for the boosted block.
8. The node switches to the minority fork. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L127-165)
```haskell
-- | VR-1A: the voter has seen the certificate for the previous round, and the
-- certificate was received in the first X slots after the start of the round.
perasVR1A ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR1A
  PerasVotingView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    VR1A := vr1a1 :/\: vr1a2
   where
    -- The latest certificate seen is from the previous round
    vr1a1 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0

    -- The latest certificate seen was received within X slots from the start
    -- of its round
    vr1a2 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its arrival time
        NotOrigin cert ->
          lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True

    _X =
      SlotNo $
        unPerasCertArrivalThreshold $
          perasCertArrivalThreshold perasParams
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
