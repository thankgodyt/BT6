### Title
Missing Round-Number Deadline Check in `validatePerasVote` Allows Stale/Future Votes to Be Accepted Indefinitely - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production default implementation of `validatePerasVote` in `BlockSupportsPeras` does not check whether the vote's embedded round number (`pvVoteRound`) matches the current Peras round. An unprivileged peer can send votes for arbitrary past or future rounds; these votes pass validation, are stored in the `PerasVoteDB`, and can accumulate toward quorum — enabling unauthorized certificate generation for rounds other than the one currently in progress.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that every inbound vote must pass before being stored. The production default instance (the only instance in the codebase, explicitly marked as the catch-all for all block types) is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

The `PerasVote blk` struct carries `pvVoteRound :: PerasRoundNo`, `pvVoteBlock :: Point blk`, and `pvVoteVoterId :: PerasVoterId`. The validation function receives `_params` (ignored) and `stakeDistr`, but **never receives the current round number** and **never inspects `pvVoteRound`**. The only check performed is whether the voter's ID appears in the stake distribution. [2](#0-1) 

The inbound processing path in `processVotes` calls this `validateVote` callback directly. The function signature does not thread the current round number through to the validator:

```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
``` [3](#0-2) 

Once a vote passes `validateVote`, it is timestamped and unconditionally added to the `PerasVoteDB` via `addVote`. The `implAddVote` function in the DB implementation also performs no round-number check: [4](#0-3) 

The garbage-collection mechanism (`garbageCollect`) removes votes only when their **target slot** is older than a threshold — not when their round number is stale. The codebase itself acknowledges that an attacker can defeat GC by supplying votes with targets far in the future:

> "This conservative approach could cause round states to be kept for a long time if an attacker keeps adding votes for a given round but with a target far into the future" [5](#0-4) 

By contrast, the Peras certificate-inclusion logic and voting-rules engine (`perasVR1A`, `perasVR2A`, etc.) do reason about round numbers — but these rules govern **when a node decides to cast its own vote**, not whether an **inbound vote from a peer** is temporally valid. [6](#0-5) 

---

### Impact Explanation

**Unauthorized certificate generation for arbitrary rounds.** Because `validatePerasVote` accepts any vote whose signer appears in the stake distribution regardless of round, an attacker controlling multiple stake-pool identities (or colluding with legitimate voters) can:

1. **Replay past-round votes**: Send votes for a round that has already concluded. If enough stake accumulates in the `PerasVoteDB` for that past round, `implAddVote` calls `updatePerasRoundVoteStates` → `forgePerasCert`, producing a `ValidatedPerasCert` for a past round. This certificate boosts a block that was not the legitimate winner of that round, artificially inflating its chain weight.

2. **Pre-position future-round votes**: Send votes for a round that has not yet started. These votes are stored and will count toward quorum when that round arrives, even though the voter had no knowledge of the actual chain state at that future time. This is the direct analog of the "execute a signed request long after the context has changed" scenario in the original report.

Both paths lead to unauthorized certificate acceptance, which directly affects Peras chain-weight calculations and can cause an honest node to prefer a non-canonical chain. [7](#0-6) 

---

### Likelihood Explanation

The entry point is the Peras vote mini-protocol, reachable by any unprivileged peer. No special keys or privileges are required — only the ability to construct a `PerasVote blk` with an arbitrary `pvVoteRound` and a `pvVoteVoterId` that appears in the current stake distribution. Any node operator running a registered stake pool can craft such a message. The attack requires no brute force and no cryptographic compromise; it exploits a missing bounds check in the validation logic. [8](#0-7) 

---

### Recommendation

1. **Add the current round number to `validatePerasVote`'s signature** (or pass it via `PerasCfg blk`) so that the validator can reject votes whose `pvVoteRound` does not equal the current round.

2. **Enforce the check in `processVotes`**: the current round should be read from a shared STM variable and compared against each incoming vote's `pvVoteRound` before the vote is forwarded to `validateVote`.

3. **Add a round-number check in `implAddVote`** as a defense-in-depth measure, analogous to how the Praos KES validation checks `c0 <= kp < c0 + MaxKESEvo`: [9](#0-8) 

4. **Resolve the tracked issue** `https://github.com/tweag/cardano-peras/issues/120` which explicitly acknowledges that `validatePerasVote` and `validatePerasCert` are stubs that need full validation logic.

---

### Proof of Concept

```
Attacker (unprivileged peer, controls stake pool P):

1. Observe current round R (e.g., R = 50).
2. Construct PerasVote { pvVoteRound = 1, pvVoteBlock = <block B from round 1>, pvVoteVoterId = P }.
3. Send this vote (and colluding votes from other pools) to an honest node via the Peras vote mini-protocol.
4. processVotes calls validatePerasVote: P is in stakeDistr => Right ValidatedPerasVote.
5. implAddVote stores the vote; if quorum is reached for round 1 / block B,
   forgePerasCert produces ValidatedPerasCert { pcCertRound = 1, pcCertBoostedBlock = B }.
6. This certificate is accepted by the ChainDB and adds Peras weight to block B,
   potentially causing chain selection to prefer a fork containing B over the honest chain.
```

The `addVote` path that leads to certificate forging: [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-303)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-236)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L301-314)
```haskell
      let
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
