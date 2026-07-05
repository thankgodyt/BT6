### Title
Peras `validatePerasVote` omits round-number check, allowing votes for arbitrary past/future rounds to be accepted — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production implementation of `validatePerasVote` — the sole instance of `BlockSupportsPeras` in the codebase — only checks whether the voter has stake in the current stake distribution. It does not verify that the vote's embedded round number (`pvVoteRound`) corresponds to the current Peras round. Because this function is wired directly into the inbound vote processing path (`makePerasVotePoolWriterFromChainDB` → `processVotes`), any unprivileged peer can submit crafted votes for arbitrary past or future rounds, which are accepted, stored, and allowed to contribute toward quorum.

---

### Finding Description

**Root cause — `validatePerasVote` ignores round number**

The only `BlockSupportsPeras` instance in the repository is the catch-all degenerate instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [1](#0-0) 

The function signature accepts `_params` (which carries `perasRoundLength`, `perasBlockMinSlots`, and all other temporal parameters) but discards it entirely. The only check performed is `lookupPerasVoteStake`, which looks up the voter's `PerasVoterId` in the stake distribution map:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [2](#0-1) 

No check is made that `pvVoteRound` (the round number embedded in the vote) matches the current Peras round, falls within any valid window, or satisfies any temporal constraint.

**Production entry path — `makePerasVotePoolWriterFromChainDB`**

This incomplete validator is wired directly into the production inbound-vote handler:

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
``` [3](#0-2) 

`processVotes` accepts any vote that passes `validatePerasVote`, timestamps it, and adds it to the `PerasVoteDB` via `ChainDB.addPerasVoteWithAsyncCertHandling`. There is no subsequent round-number gate: [4](#0-3) 

**No round check anywhere in the pipeline**

`implAddVote` in `PerasVoteDB/Impl.hs` also carries an explicit TODO acknowledging missing validation logic:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote perasCfg ...
``` [5](#0-4) 

The only round-related assertion in the aggregation layer is a debug `assert` (not a security check) that the vote's round matches the aggregate bucket it is placed into — it does not verify the round is the *current* round:

```haskell
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
``` [6](#0-5) 

**`getVotingCommitteeForElection` is unimplemented**

The function responsible for resolving which committee applies to a given election across epoch boundaries is a stub that unconditionally throws a Haskell `error`:

```haskell
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
``` [7](#0-6) 

This means that even if round-number validation were added, the committee lookup needed to verify *which* committee is authoritative for a given round/epoch is absent.

---

### Impact Explanation

An unprivileged peer can craft `PerasVote` messages with any `pvVoteRound` value and any `pvVoteVoterId` that appears in the current stake distribution. Because `validatePerasVote` only checks stake membership:

- **Votes for past rounds** are accepted and stored. If the targeted round is still within the GC window, accumulated votes can push that round's tally above the quorum threshold, causing the node to forge a `PerasCert` for a past round and include it in a future block. This directly affects chain selection via the Peras boost weight (`perasWeight`), allowing an adversary to retroactively certify a block on a non-canonical chain.

- **Votes for future rounds** are accepted and stored. When that round arrives, pre-staged votes immediately contribute to quorum without any honest node having observed the candidate block, enabling unauthorized certificate generation for a block the local node has not yet validated.

Both scenarios constitute a **bypass of Peras voting/certificate checks** that enables unauthorized certificate acceptance, matching the "Critical" impact tier: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance."* [8](#0-7) 

---

### Likelihood Explanation

The attack requires only that the adversary:
1. Connect to a target node as a peer (standard network participation).
2. Know any `PerasVoterId` present in the current stake distribution (publicly observable on-chain).
3. Send a `PerasVote` message with an arbitrary `pvVoteRound` via the object-diffusion mini-protocol.

No key material, stake majority, or privileged access is required. The degenerate `BlockSupportsPeras` instance is the only one in the codebase (confirmed: `grep` finds exactly two `instance.*BlockSupportsPeras` declarations, both in `SupportsPeras.hs`), so there is no more-specific override that would add the missing check. [9](#0-8) 

---

### Recommendation

1. **Add round-number validation to `validatePerasVote`**: the vote's `pvVoteRound` must equal the current Peras round (derivable from the current slot and `perasRoundLength`). Votes for any other round must be rejected with a typed `PerasValidationErr` variant.

2. **Implement `getVotingCommitteeForElection`** in `AcrossEpochs.hs` so that the correct epoch's committee is used when validating votes that arrive near epoch boundaries.

3. **Resolve the TODO at `implAddVote`** (`PerasVoteDB/Impl.hs` line 172) by adding the non-trivial validation logic referenced in issue #120, including at minimum: round-number bounds, block-age check (`perasBlockMinSlots`), and certificate-age check (`perasCertMaxRounds`).

---

### Proof of Concept

```
Attacker (peer) connects to HonestNode.

1. Attacker observes stake distribution; picks VoterId V with stake S.
2. Current Peras round = R (e.g., round 500).
3. Attacker crafts PerasVote { pvVoteRound = R - 200, pvVoteBlock = B_old, pvVoteVoterId = V }
   where B_old is a block on a minority fork from round R-200.
4. Attacker sends the vote via the object-diffusion mini-protocol.
5. HonestNode calls makePerasVotePoolWriterFromChainDB → processVotes →
   validatePerasVote mkPerasParams sd vote.
6. validatePerasVote finds V in the stake distribution → returns Right (ValidatedPerasVote ...).
7. Vote is stored in PerasVoteDB under round R-200.
8. If attacker repeats with enough distinct VoterIds to exceed the quorum threshold,
   implAddVote triggers forgePerasCert for round R-200, producing a ValidatedPerasCert
   boosting B_old with weight perasWeight = 15.
9. This certificate is included in a future block, causing HonestNode's chain-selection
   to prefer the minority fork over the canonical chain.
``` [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-183)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-246)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L206-207)
```haskell
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L69-74)
```haskell
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```
