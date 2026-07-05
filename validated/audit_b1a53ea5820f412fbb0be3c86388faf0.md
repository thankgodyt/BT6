### Title
Peras `validatePerasVote` Accepts Votes for Arbitrary Past Rounds Without Staleness or Signature Check — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the only instance in the codebase — implements `validatePerasVote` as a stub that only checks stake-distribution membership. It performs no round-staleness check and no cryptographic signature verification. Because this catch-all instance applies to all block types, the production vote-ingestion path (`processVotes`) accepts votes for any past round from any unprivileged peer, enabling stale-vote injection that can forge certificates for already-concluded rounds and distort chain selection.

---

### Finding Description

`BlockSupportsPeras` is the type class that governs Peras vote and certificate validation. The only instance in the repository is a catch-all degenerate instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
```

Its `validatePerasVote` implementation is:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

Two critical checks are absent:

1. **No round-staleness check.** The vote's `pvVoteRound` is never compared to the current round. A vote signed for round N can be submitted and accepted at any future time until garbage collection fires.
2. **No cryptographic signature verification.** The degenerate `PerasVote` data type carries no signature field, and the stub ignores the `_params` argument entirely.

The production entry point for inbound peer votes is `processVotes` in `ObjectPool/PerasVote.hs`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

This calls the stub directly. Any vote that names a voter ID present in the current stake distribution is accepted, regardless of round number or authenticity.

Once accepted, `implAddVote` in `PerasVoteDB/Impl.hs` feeds the vote into `updatePerasRoundVoteStates`, which accumulates stake toward quorum for the vote's round. When accumulated stake crosses the threshold, `forgePerasCert` is called and a `ValidatedPerasCert` is stored — permanently, until GC.

The GC mechanism (`implGarbageCollect`) removes rounds only when their youngest targeted slot is strictly older than the GC threshold. An attacker can delay GC indefinitely for a target round by injecting votes that point to a recent block slot, as noted in the code itself:

```
-- NOTE:
-- This conservative approach could cause round states to be kept
-- for a long time if an attacker keeps adding votes for a given
-- round but with a target far into the future,
-- see https://github.com/tweag/cardano-peras/issues/218
```

---

### Impact Explanation

Peras certificates boost chain-selection weight. A certificate forged for a past round's block adds `vpcCertBoost` (the `perasWeight` parameter) to that block's chain weight. An unprivileged peer that injects enough stale votes for a past round can cause an honest node to forge a certificate for a block that should not be certified, making the node prefer a non-canonical chain. This materially weakens vote and certificate authorization and can distort chain selection beyond the intended security assumptions.

**Impact class:** Medium — public miniprotocol flaw that materially weakens vote/certificate authorization without relying on DoS; escalates toward High if the boosted chain diverges from the canonical chain.

---

### Likelihood Explanation

The entry path is the Peras vote diffusion miniprotocol, reachable by any unprivileged peer. The attacker needs only to know a valid `PerasVoterId` (a `KeyHash StakePool`, which is public on-chain data) and to send a `PerasVote` message naming that voter ID and any past round number. No key material is required because the stub performs no signature check. The attack is therefore trivially executable by any connected peer once the Peras diffusion path is active.

---

### Recommendation

1. **Enforce round-staleness in `validatePerasVote`:** Reject votes whose `pvVoteRound` is not the current round (or within a small configurable window). This mirrors the "expiry" mechanism that the external report recommends for RFQ orders.
2. **Verify cryptographic signatures before accepting votes:** The concrete `PerasVote.V1` type already carries a `pvSignature` field; the `BlockSupportsPeras` instance for the production block type must verify it using `verifyVoteSignature` from `Committee.Crypto`.
3. **Replace the degenerate catch-all instance** with a proper per-era instance that enforces all invariants, rather than relying on TODO stubs in production code paths.
4. **Add a round-expiry check in `implAddVote`** as a defense-in-depth measure, independent of the per-vote validation.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects and sends a batch of `PerasVote` messages via the Peras vote diffusion miniprotocol.
2. `processVotes` is called in `ObjectPool/PerasVote.hs` (lines 178–201).
3. For each vote, `validatePerasVote mkPerasParams sd vote` is called (line 111).
4. The stub at `BlockSupportsPeras.hs` lines 363–371 checks only `lookupPerasVoteStake vote stakeDistr` — passes if the voter ID is in the stake distribution.
5. The validated vote is timestamped and passed to `PerasVoteDB.addVote` (line 112).
6. `implAddVote` (lines 174–246 of `PerasVoteDB/Impl.hs`) calls `updatePerasRoundVoteStates` for the vote's round, accumulating stake.
7. When accumulated stake for a past round crosses the quorum threshold, `forgePerasCert` is called and a `ValidatedPerasCert` is stored.
8. The forged certificate boosts the targeted block's chain-selection weight, causing the honest node to prefer a non-canonical chain.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-113)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L174-246)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L302-314)
```haskell
        -- First, determine which rounds to delete based on the round vote
        -- state: a round is deleted only when the youngest target of all its
        -- votes is strictly older than the GC threshold.
        --
        -- NOTE:
        -- This conservative approach could cause round states to be kept
        -- for a long time if an attacker keeps adding votes for a given
        -- round but with a target far into the future,
        -- see https://github.com/tweag/cardano-peras/issues/218
        (roundsToDelete, pvsRoundVoteStates') =
          Map.partition
            (\rvs -> getPerasRoundVoteStateMaxTargetedSlot rvs < NotOrigin slotNo)
            pvdsRoundVoteStates
```
