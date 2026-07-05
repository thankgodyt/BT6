### Title
Missing Block-on-Chain Membership Check in Peras Vote Validation Enables Certificate Forgery for Non-Canonical Blocks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function — the sole validation gate for inbound Peras votes — only checks that the voter has stake in the distribution. It does **not** verify that the voted block (`pvVoteBlock`) actually exists on the current chain. An unprivileged peer who is a legitimate voter can send votes for arbitrary off-chain or non-existent blocks. If enough such votes accumulate to reach quorum, a `ValidatedPerasCert` is automatically forged for the non-canonical block and submitted to the ChainDB, where it can boost that block's weight in chain selection.

---

### Finding Description

The vulnerability class from the external report is a **missing membership/ownership check**: `removeCollateralWLpTo` verified the caller's position ID but never checked whether the supplied `tokenId` actually belonged to that position, allowing a caller to operate on a resource from a completely different context. The check was conditional — it only fired on full removal (`newWLpAmt == 0`), not on partial removal.

The exact structural analog exists in the Peras vote-validation pipeline.

**`validatePerasVote`** is the function called for every vote received from a peer (via `processVotes` in `ObjectPool/PerasVote.hs`). Its current implementation:

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

Note that `_params` is entirely ignored (underscore prefix). The function checks only one thing: whether `pvVoteVoterId` (the voter's ID) is present in `stakeDistr`. It does **not** check whether `pvVoteBlock` (the block being voted for) is present on the current chain, in the VolatileDB, or in the ImmutableDB.

This is the direct analog of the missing `posCollInfo.ids[_wlp].contains(_tokenId)` check: the caller's identity (voter stake) is verified, but the resource being acted upon (the target block) is never verified to belong to the current context (the canonical chain).

The inbound path is:

1. Peer sends `[PerasVote blk]` over the network mini-protocol.
2. `processVotes` (in `ObjectPool/PerasVote.hs`) filters already-known votes, then calls `validateVote` — which resolves to `validatePerasVote` — for each remaining vote.
3. Votes that pass are timestamped and forwarded to `addVote` (the `PerasVoteDB.addVote` field).
4. `implAddVote` (in `PerasVoteDB/Impl.hs`) calls `updatePerasRoundVoteStates`, which aggregates stake per `(roundNo, pvVoteBlock)` target.
5. When accumulated stake for any target exceeds the quorum threshold, `updateCandidateVoteState` calls `forgePerasCert`, producing a `ValidatedPerasCert` whose `pcCertBoostedBlock` is the attacker-supplied block point.
6. `addPerasCertAsync` / `chainSelSync` then processes this certificate against the ChainDB, potentially boosting the non-canonical block's weight in chain selection.

The `implAddVote` comment at line 172–173 explicitly acknowledges the gap:

> `-- TODO: we will need to update this method with non-trivial validation logic`
> `-- see https://github.com/tweag/cardano-peras/issues/120`

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A legitimate voter (any pool with positive stake in the current epoch's distribution) can send votes whose `pvVoteBlock` points to a block on a competing fork, a stale block, or a fabricated point. Because `validatePerasVote` never checks block existence on the canonical chain, these votes are accepted, stored, and aggregated. Once the attacker's accumulated stake crosses the quorum threshold, a `ValidatedPerasCert` is forged for the off-chain block and injected into the ChainDB's chain-selection queue. The Peras weight boost attached to that certificate (`vpcCertBoost`) can cause the node to switch to the non-canonical fork, violating chain-selection safety.

---

### Likelihood Explanation

**Medium.** The attacker must control at least one pool with positive stake in the current epoch's stake distribution to pass the `lookupPerasVoteStake` check. This is a realistic condition for any active stake pool operator. Furthermore, the TODO comment also implies that cryptographic signature verification is not yet implemented; if that is confirmed, the barrier drops to zero — any peer could forge votes for any voter ID that has stake, without holding the corresponding private key.

---

### Recommendation

1. **Add a block-on-chain check inside `validatePerasVote`**: before accepting a vote, verify that `pvVoteBlock` is reachable from the current chain tip (present in the VolatileDB or ImmutableDB). Reject the vote — and disconnect the peer — if the block is unknown.

2. **Implement cryptographic signature verification** as indicated by the referenced issue (https://github.com/tweag/cardano-peras/issues/120). The `_params` argument is already threaded into `validatePerasVote` but is currently ignored; it should carry the verification keys needed to authenticate the vote body.

3. **Validate the round number** against the current slot/epoch to reject votes for rounds that are too far in the past or future.

---

### Proof of Concept

```
1. Attacker controls pool P with any positive stake in the current epoch.
2. Attacker constructs PerasVote { pvVoteRound = R, pvVoteBlock = offChainPoint, pvVoteVoterId = P }.
3. Attacker sends this vote to an honest node via the Peras vote mini-protocol.
4. processVotes calls validatePerasVote:
     lookupPerasVoteStake vote stakeDistr  -- succeeds: P has stake
     -- pvVoteBlock is never checked against the chain
   => vote is accepted as ValidatedPerasVote.
5. implAddVote aggregates the vote under (R, offChainPoint).
6. If attacker controls enough stake to reach quorum (or can repeat with multiple
   colluding pools), updateCandidateVoteState triggers forgePerasCert, producing
   ValidatedPerasCert { pcCertBoostedBlock = offChainPoint, vpcCertBoost = W }.
7. addPerasCertAsync submits the certificate to chainSelSync.
8. Chain selection applies the Peras weight boost to offChainPoint, potentially
   causing the honest node to switch to the non-canonical fork.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-198)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L569-587)
```haskell
updateCandidateVoteState ::
  StandardHash blk =>
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Candidate ->
  Either
    (PerasForgeErr blk)
    (PerasVoteStateCandidateOrWinner blk)
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L601-641)
```haskell
-------------------------------------------------------------------------------}

-- | The outcome of processing a Peras certificate w.r.t. chain selection.
data AddPerasCertChainSelOutcome
  = -- | The certificate was too old to influence chain selection (the boosted
    -- block is already immutable), so it was ignored entirely.
    PerasCertIgnoredTooOld
  | -- | The certificate was not processed because the ChainDB was closing.
    PerasCertNotProcessedClosing
  | -- | The certificate was processed; whether it was actually added to the DB
    -- or was a duplicate is captured by the inner 'AddPerasCertResult'.
    PerasCertProcessed AddPerasCertResult
  deriving stock (Generic, Eq, Ord, Show)
  deriving anyclass NoThunks

newtype AddPerasCertPromise m = AddPerasCertPromise
  { waitPerasCertProcessed :: m AddPerasCertChainSelOutcome
  -- ^ Wait until the Peras certificate has been processed (which potentially
  -- includes switching to a different chain). If the PerasCertDB did already
  -- contain a certificate for this round, the certificate is ignored (as the
  -- two certificates must be identical because certificate equivocation is
  -- impossible).
  }

addPerasCertSync ::
  IOLike m =>
  ChainDB m blk -> WithArrivalTime (ValidatedPerasCert blk) -> m AddPerasCertChainSelOutcome
addPerasCertSync chainDB cert =
  waitPerasCertProcessed =<< addPerasCertAsync chainDB cert

addPerasVoteSync ::
  IOLike m =>
  ChainDB m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe AddPerasCertChainSelOutcome)
addPerasVoteSync chainDB vote = do
  (voteRes, mCertPromise) <- addPerasVoteWithAsyncCertHandling chainDB vote
  mCertRes <- case mCertPromise of
    Nothing -> return Nothing
    Just certPromise -> Just <$> waitPerasCertProcessed certPromise
  return (voteRes, mCertRes)
```
