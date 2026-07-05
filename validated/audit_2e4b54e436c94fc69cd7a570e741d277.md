### Title
Missing Active-Round Validation in Peras Vote Ingestion Allows Stale/Crafted Vote Aggregation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs`)

---

### Summary

The `implAddVote` function in the Peras vote database implementation accepts and aggregates incoming votes from peers without verifying that the vote's round corresponds to the currently active Peras round or that the vote's target block is on the current chain. An explicit `TODO` in the source acknowledges this gap. An unprivileged peer can send crafted votes for arbitrary rounds and arbitrary block targets; if enough stake-weighted votes accumulate for a non-canonical block, a certificate is forged for it, boosting that block's weight in Peras chain selection and potentially causing honest nodes to prefer a non-canonical chain.

---

### Finding Description

The `implAddVote` function in `PerasVoteDB/Impl.hs` is the entry point for adding a validated Peras vote to the in-memory vote database. Its current implementation performs only one check: deduplication via the vote ID set. It then unconditionally calls `updatePerasRoundVoteStates`, which aggregates the vote into the per-round state map keyed by `PerasRoundNo`. [1](#0-0) 

The source contains an explicit acknowledgment of the missing validation:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [2](#0-1) 

The `updatePerasRoundVoteStates` function, which is called unconditionally, accepts votes for any `PerasRoundNo` — past, present, or future — and creates a fresh round state if none exists. The only round-consistency check present is an `assert` inside `updatePerasRoundVoteState`, which is a debug-only guard that can be compiled away and only verifies that the vote's round matches the map entry being updated, not that the round is currently active:

```haskell
assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
``` [3](#0-2) 

The upstream `processVotes` function in the object diffusion layer calls a `validateVote` callback before calling `addVote`, but this callback produces a `ValidatedPerasVote` — a type-level marker — and the TODO in `implAddVote` explicitly states that the DB-level function itself still needs to perform the chain-state-aware validation (e.g., checking the active round, checking the target block is on the current chain). [4](#0-3) 

The missing checks are directly analogous to the reported vulnerability: messages (votes) are processed and aggregated without verifying they correspond to the currently active consensus state (active round / current chain tip).

---

### Impact Explanation

Peras certificates are used to assign weight boosts to blocks during chain selection. A certificate for round R certifying block B causes honest nodes to prefer any chain containing B over chains of equal or slightly greater length that lack a certificate. [5](#0-4) 

If `implAddVote` accepts votes for stale rounds or for block targets not on the current chain, an adversary controlling sufficient stake can:

1. Send crafted votes targeting a non-canonical fork block in any round (past or future).
2. Accumulate enough stake-weighted votes to trigger `votesReachQuorum`, causing `forgePerasCert` to produce a certificate for the fork block.
3. The forged certificate boosts the fork chain's weight in Peras chain selection, causing honest nodes to switch to the non-canonical chain. [6](#0-5) 

This maps to: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

The attacker-controlled entry path is the Peras vote object diffusion mini-protocol, which is reachable by any unprivileged peer. No special privileges, key compromise, or operator access are required to send crafted votes. The adversary must control enough stake to reach the quorum threshold for the targeted round, but the absence of active-round and chain-membership checks means they can target any round and any block point without restriction, including replaying votes from past rounds or pre-staging votes for future rounds. The TODO comment confirms this is a known, unresolved gap in the production code.

---

### Recommendation

`implAddVote` (and/or the `validateVote` callback supplied to `processVotes`) must be updated to:

1. **Check active round**: Reject votes whose `PerasRoundNo` does not correspond to the currently active Peras round (or a small window around it). Votes for rounds that have already concluded or are too far in the future must be rejected.
2. **Check chain membership**: Verify that the vote's target block (`getPerasVoteBlock`) is a known block on the current chain (or at least in the VolatileDB), not an arbitrary point.
3. **Replace the `assert` with a runtime error**: The round-consistency check in `updatePerasRoundVoteState` is a debug-only `assert`; it must be a hard runtime rejection.

This mirrors the fix applied in the referenced Lombard report: each incoming message must be validated against the currently active consensus state before being processed.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the Peras vote object diffusion mini-protocol.
2. Construct a `PerasVote` with:
   - `voteRound` set to any `PerasRoundNo` (e.g., a past round that has already concluded, or the current round).
   - `voteBlock` set to the `Point` of a fork block not on the honest chain.
   - A valid committee membership proof and signature for the attacker's stake key.
3. Send the vote. `processVotes` calls `validateVote` (which checks the cryptographic proof) and then calls `addVote` = `implAddVote`.
4. `implAddVote` performs only deduplication and calls `updatePerasRoundVoteStates`, which creates or updates the round state for the targeted round without checking whether that round is currently active or whether the target block is on the current chain.
5. Repeat with additional stake keys until `votesReachQuorum` returns `Just`, triggering `forgePerasCert` and producing a certificate for the fork block.
6. The certificate is now in the node's `PerasVoteDB` and will be used to boost the fork chain's weight in subsequent Peras chain selection, causing the node to prefer the non-canonical chain. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-213)
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

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L36-46)
```haskell
-- = State Machine
--
-- For every round being voted for, the aggregation follows a state machine:
--
-- 1. __Quorum not reached__: multiple block targets are candidates, each
--    accumulating votes and stake. All targets compete to reach quorum first.
--
-- 2. __Quorum reached__: once a target reaches quorum, it becomes the winner
--    and a certificate is forged. All other targets become losers and continue
--    tracking votes without affecting the outcome.
--
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L206-207)
```haskell
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L319-362)
```haskell
updatePerasRoundVoteStates ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  Map PerasRoundNo (PerasRoundVoteState blk) ->
  Either
    (UpdateRoundVoteStateError blk)
    (PerasRoundVoteState blk, Map PerasRoundNo (PerasRoundVoteState blk))
updatePerasRoundVoteStates vote cfg =
  alterMapAndReturnUpdatedValue
    updateMaybePerasRoundVoteState
    (getPerasVoteRound vote)
 where
  -- We use the Functor instance of `Compose (Either e) ((,) s)` ≅
  -- `λt. Either e (s, t)` in `Map.alterF`. That way, we can return both the
  -- updated map and the updated leaf in one pass, and still handle errors.
  alterMapAndReturnUpdatedValue ::
    Ord k =>
    (Maybe a -> Either e (a, a)) ->
    k ->
    Map k a ->
    Either e (a, Map k a)
  alterMapAndReturnUpdatedValue f k =
    getCompose . Map.alterF (fmap Just . (Compose . f)) k

  -- If there is no existing state for the vote's round, create a fresh one.
  existingOrFreshRoundVoteState ::
    Maybe (PerasRoundVoteState blk) ->
    PerasRoundVoteState blk
  existingOrFreshRoundVoteState =
    fromMaybe (freshRoundVoteState (getPerasVoteRound vote))

  -- Update the round state, creating a fresh one if necessary, and returning
  -- the updated state.
  updateMaybePerasRoundVoteState ::
    Maybe (PerasRoundVoteState blk) ->
    Either
      (UpdateRoundVoteStateError blk)
      (PerasRoundVoteState blk, PerasRoundVoteState blk)
  updateMaybePerasRoundVoteState mRoundState = do
    let roundState = existingOrFreshRoundVoteState mRoundState
    newRoundState <- updatePerasRoundVoteState vote cfg roundState
    pure (newRoundState, newRoundState)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
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
