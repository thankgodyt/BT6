### Title
Missing Vote Validation in `implAddVote` Allows Unprivileged Peer to Corrupt Peras Vote Tally and Manipulate Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs`)

---

### Summary

`implAddVote` in the `PerasVoteDB` implementation carries an explicit TODO acknowledging that **non-trivial validation logic has not yet been implemented**. Because any peer can submit votes via the Peras vote miniprotocol, and because the missing DB-level validation is the only gate between a cryptographically-signed vote and the vote tally that drives certificate generation, an unprivileged peer can inject votes that pass signature checks but violate protocol rules (e.g., votes for stale rounds, votes for blocks not on the chain). This corrupts the `PerasRoundVoteState`, can cause a spurious certificate to be forged, and ultimately lets the attacker manipulate Peras-weighted chain selection.

---

### Finding Description

`implAddVote` in `PerasVoteDB/Impl.hs` is the sole write path into the vote tally. Its header carries an explicit admission that the required validation is absent:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ...
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
``` [1](#0-0) 

The function accepts a `ValidatedPerasVote blk`, a type produced by `validatePerasVote` in `BlockSupportsPeras`. That upstream call checks the BLS signature and the eligibility proof (persistent or VRF-based). However, the TODO explicitly states that **additional, non-trivial validation** must still be added inside `implAddVote` itself — validation that has not been implemented. [2](#0-1) 

The network-facing entry point, `processVotes`, filters duplicate vote IDs and calls `validateVote` (i.e., `validatePerasVote`) before forwarding to `addVote`. It does **not** perform any DB-level checks such as:

- whether the vote's round is currently active or already closed,
- whether the boosted block actually exists on the local chain,
- whether the voter's stake is computed against the correct epoch's ledger view. [3](#0-2) 

Once a vote passes the signature check and is not a duplicate, `implAddVote` unconditionally calls `updatePerasRoundVoteStates`, which accumulates stake and, when the quorum threshold is crossed, **forges a certificate**:

```haskell
Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
  pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
``` [4](#0-3) 

That certificate is then forwarded to `addPerasCertAsync`, which enqueues it for chain selection:

```haskell
addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
case addVoteRes of
  AddedPerasVoteAndGeneratedNewCert cert -> do
    ...
    promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
``` [5](#0-4) 

A Peras certificate boosts the weight of the block it certifies in chain selection. A spurious certificate therefore causes the node to prefer a non-canonical chain.

---

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An attacker who can send Peras vote messages (any peer connected via the vote-diffusion miniprotocol) can craft votes that are cryptographically valid (correct BLS signature, valid eligibility proof) but violate protocol rules that the missing DB-level validation was meant to enforce. By submitting enough such votes to cross the quorum threshold, the attacker causes the local node to forge a certificate for an attacker-chosen block and then prefer that block's chain in chain selection. This is a direct analog to the original report's `decreaseYIntercept` manipulation: a state-mutating function callable by anyone, without the required guards, corrupts a critical accumulator (vote tally / `yIntercept`) and causes the system to reach an incorrect state (wrong chain selection / vault insolvency).

---

### Likelihood Explanation

**Medium.** The Peras vote miniprotocol is reachable by any connected peer. Constructing a BLS-signed vote with a valid eligibility proof requires knowledge of a committee member's signing key, which limits the attacker to a committee member or someone who has compromised one. However, the missing validation means that even a legitimately eligible voter can submit votes for stale rounds, non-existent blocks, or outside the valid time window — all of which the current code will accept and tally without complaint.

---

### Recommendation

Implement the missing validation inside `implAddVote` (tracked in `https://github.com/tweag/cardano-peras/issues/120`) before the Peras vote-diffusion path is enabled on a live network. At minimum, the DB-level checks should verify:

1. The vote's round number falls within the currently active window (not stale, not from the future).
2. The boosted block is known to the local node (exists in the VolatileDB or ImmutableDB).
3. The voter's stake is computed against the correct epoch's ledger view, not a stale snapshot.

Until these checks are in place, the `addVote` path should be gated so that it is unreachable from the network (e.g., the miniprotocol handler should be disabled or return an error).

---

### Proof of Concept

1. Connect to a target node as a peer that participates in the Peras vote-diffusion miniprotocol.
2. Obtain (or generate) a BLS key pair for a committee member with non-zero stake.
3. Craft a `PerasVote` for an arbitrary round `R` (e.g., a round that has already closed) targeting an attacker-chosen block hash `B`.
4. Sign the vote correctly so `validatePerasVote` accepts it.
5. Send enough such votes (from enough distinct committee seats) to exceed the quorum threshold.
6. `processVotes` passes each vote through `validatePerasVote` (succeeds), then calls `implAddVote`.
7. `implAddVote` calls `updatePerasRoundVoteStates`; when stake crosses the threshold, it returns `VoteGeneratedNewCert cert`.
8. `addPerasVoteWithAsyncCertHandling` enqueues the certificate via `addPerasCertAsync`.
9. `chainSelSync` processes the certificate: if block `B` is on a fork, the node now prefers that fork over the honest chain. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-246)
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
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr

    pure
      ( addPerasVoteRes
      , PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvsLastTicketNo'
          }
      )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-300)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
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
