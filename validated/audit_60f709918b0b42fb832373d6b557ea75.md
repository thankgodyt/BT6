### Title
Missing Round-Number Bound in `validatePerasVote` Allows Acceptance of Votes for Arbitrary Rounds - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function in the default `BlockSupportsPeras` instance accepts inbound Peras votes without checking whether the vote's round number corresponds to the current or any valid round. An unprivileged peer can submit votes for arbitrary past or future rounds; these pass validation, are stored in the `PerasVoteDB`, and can trigger premature certificate generation that materially affects Peras weight-based chain selection.

---

### Finding Description

The analog to "missing deadline" in this codebase is the absence of a round-number (slot-time) bound on inbound Peras vote acceptance.

**Inbound vote processing path** (`processVotes` in `ObjectPool/PerasVote.hs`, lines 178–201):

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    ([], validatedVotes) ->
      mapM_ (addVote . WithArrivalTime now) validatedVotes
```

The `validateVote` callback used in production (`makePerasVotePoolWriterFromChainDB`, line 141) delegates to `validatePerasVote`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

The default `validatePerasVote` implementation (lines 363–371) only checks stake distribution membership:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The `_params` argument (which carries `PerasParams`, including round-length information) is **discarded**. The `pvVoteRound` field embedded in the vote is never compared against the current round. A vote for round `N+1000` is accepted identically to a vote for the current round, as long as the voter ID appears in the stake distribution.

Once accepted, the vote is stored in `PerasVoteDB` via `implAddVote` (lines 183–246 of `PerasVoteDB/Impl.hs`), which calls `updatePerasRoundVoteStates`. If enough such votes accumulate for a future round to exceed the quorum threshold, `AddedPerasVoteAndGeneratedNewCert` is returned and a certificate is forged for that future round. That certificate is then submitted to the `ChainDB` via `addPerasCertAsync`, where it immediately participates in Peras weight-based chain selection.

The only post-acceptance guard in the `ChainDB` model (`addPerasCert`, line 468 of `ChainDB/Model.hs`) rejects certificates whose **boosted block** is older than the immutable tip — it does not reject certificates for future rounds:

```haskell
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise = ...
```

The garbage-collection logic in `implGarbageCollect` (lines 279–335 of `PerasVoteDB/Impl.hs`) itself acknowledges that an attacker can prevent GC by supplying votes with targets far in the future:

> "This conservative approach could cause round states to be kept for a long time if an attacker keeps adding votes for a given round but with a target far into the future, see https://github.com/tweag/cardano-peras/issues/218"

The voting rules (`isPerasVotingAllowed`, `perasVR1A`/`VR1B`/`VR2A`/`VR2B` in `Peras/Voting/Rules.hs`) govern when a **local node** casts votes; they are not applied to **inbound** votes from peers. There is no equivalent inbound gate.

---

### Impact Explanation

**Impact: Medium** — Public miniprotocol flaw that materially weakens Peras vote and certificate authorization.

A crafted batch of votes for a future round `R_future`, each carrying a valid voter ID from the public stake distribution, passes `validatePerasVote` and accumulates in the `PerasVoteDB`. Once the aggregate stake exceeds the quorum threshold, a `ValidatedPerasCert` is forged for `R_future` and injected into chain selection. This certificate applies a Peras weight boost to the boosted block, causing the node to prefer a chain that should not yet be preferred under the Peras protocol. The effect is a premature, attacker-controlled chain-selection bias that bypasses the round-timing invariants of CIP-0140.

---

### Likelihood Explanation

**Likelihood: High** — The stake distribution (`PerasVoteStakeDistr`) is derived from public ledger state. Any peer that knows a valid voter ID (a public key hash present in the distribution) can craft votes for arbitrary rounds. The object-diffusion miniprotocol (`ObjectPoolWriter`) is reachable by any connected peer. No privileged access, key compromise, or stake majority is required.

---

### Recommendation

1. In `validatePerasVote`, compare `pvVoteRound` against the current round (or a small acceptable window, e.g., `[currRound - 1, currRound]`) and reject votes outside that window.
2. Pass the current round number into `validatePerasVote` (extend the `BlockSupportsPeras` class signature or the call site in `processVotes`/`makePerasVotePoolWriterFromChainDB`).
3. Until the full validation is implemented (tracked in issue #120), add at minimum a round-number staleness/futurity guard as a cheap first-pass filter before the vote enters the `PerasVoteDB`.

---

### Proof of Concept

**Entry point**: Object-diffusion miniprotocol → `makePerasVotePoolWriterFromChainDB` → `processVotes` → `validatePerasVote`.

**Attacker-controlled input**: A `PerasVote blk` with `pvVoteRound = R_future` (e.g., current round + 1000), `pvVoteBlock` pointing to any existing block, and `pvVoteVoterId` set to any voter ID present in the current `PerasVoteStakeDistr`.

**Step-by-step**:

1. Adversary connects as a peer and sends a batch of `PerasVote` objects via the object-diffusion protocol, all targeting round `R_future`.
2. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each vote. [1](#0-0) 
3. `validatePerasVote` checks only `lookupPerasVoteStake vote stakeDistr`; `pvVoteRound` is never inspected. [2](#0-1) 
4. All votes pass and are stored via `implAddVote` → `updatePerasRoundVoteStates`. [3](#0-2) 
5. When aggregate stake for `R_future` exceeds the quorum threshold, `AddedPerasVoteAndGeneratedNewCert cert` is returned and `addPerasCertAsync` is called. [4](#0-3) 
6. The certificate for `R_future` enters chain selection. The only guard (`pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m)`) does not reject future-round certificates. [5](#0-4) 
7. The Peras weight boost from the premature certificate biases chain selection toward the attacker's chosen block, ahead of the protocol-intended schedule.

The `validatePerasVote` signature accepts `PerasCfg blk` (which contains round-length and timing parameters) but the default instance discards it (`_params`), making the round-number check structurally absent rather than merely misconfigured. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L299-303)
```haskell
  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-246)
```haskell
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L467-472)
```haskell
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
```
