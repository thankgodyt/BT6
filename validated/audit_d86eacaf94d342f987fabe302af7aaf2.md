### Title
Intra-Batch Duplicate Voter ID Not Detected in `processVotes`, Allowing Equivocation Without Peer Disconnection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`)

---

### Summary

The `processVotes` function in the Peras vote diffusion mini-protocol checks for duplicate votes only against the current DB state (a snapshot taken at the start of the batch), but does not check for duplicate `PerasVoteId` values **within the incoming batch itself**. A malicious peer can send a single batch containing two votes from the same voter for the same round but targeting different blocks (equivocation). Both votes pass the deduplication filter and both pass validation. The first is added to the DB; the second is silently ignored with `PerasVoteAlreadyInDB`. The peer is **never disconnected** for equivocating.

---

### Finding Description

`processVotes` in `PerasVote.hs` implements the following two-phase pattern:

**Phase 1 — Validation (inside a single `atomically` block):**
```haskell
validationResults <- atomically $ do
  alreadyInDb <- alreadyInDbSTM                                    -- snapshot of DB at this instant
  let votesNotAlreadyInDb =
        filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
  mapM validateVote votesNotAlreadyInDb
``` [1](#0-0) 

**Phase 2 — Execution (outside the STM transaction, sequential):**
```haskell
([], validatedVotes) ->
  mapM_ (addVote . WithArrivalTime now) validatedVotes
``` [2](#0-1) 

`PerasVoteId` is defined as the pair `(roundNo, voterId)`: [3](#0-2) 

The deduplication filter `filter (not . Set.member alreadyInDb . getPerasVoteId)` removes votes whose ID is **already in the DB**. It does **not** remove votes whose ID appears more than once **within the same batch**. If a batch contains:

- `vote1 = (voter X, round R, block A)` — `PerasVoteId = (R, X)`
- `vote2 = (voter X, round R, block B)` — `PerasVoteId = (R, X)`

Both share the same `PerasVoteId`. Since neither is in the DB at the time the snapshot is taken, **both survive the filter**. Both are then validated (the current `validatePerasVote` stub only checks stake-distribution membership): [4](#0-3) 

Both pass. In Phase 2, `addVote vote1` succeeds and inserts `(R, X)` into the DB. `addVote vote2` then finds `(R, X)` already present and returns `PerasVoteAlreadyInDB` silently: [5](#0-4) 

The batch is **not rejected**. No `PerasVoteInboundException` is thrown. The peer is **not disconnected**.

The comment in `processVotes` states the design intent:
> "if /any/ vote in the batch fails validation, the entire batch is rejected by throwing a `PerasVoteInboundException` (which should make us disconnect from the distant peer)" [6](#0-5) 

Equivocation (same voter, same round, different blocks) is a protocol violation that should trigger disconnection under this stated intent, but the intra-batch duplicate check is absent.

This is the direct analog of the external report: multiple operations for the same entity (voter) are validated against the same initial state (DB snapshot), then executed sequentially. The second operation is silently swallowed at execution time rather than being caught at validation time, and the submitting peer escapes punishment.

The production entry path is `makePerasVotePoolWriterFromChainDB`, which wires `processVotes` into the live object-diffusion mini-protocol: [7](#0-6) 

---

### Impact Explanation

**Impact: Medium.**

The Peras protocol's security relies on disconnecting peers that equivocate (vote for more than one block per round). By sending a single batch with two votes sharing the same `PerasVoteId` but targeting different blocks, an unprivileged peer bypasses the disconnection mechanism entirely. The peer remains connected and can repeat the pattern indefinitely. While the consensus tally itself is not corrupted (the second vote is a no-op in the DB), the vote-authorization enforcement layer is materially weakened: equivocation within a batch is structurally undetectable and unpunishable under the current code. This matches the allowed scope: *"miniprotocol flaw that materially weakens vote authorization."*

---

### Likelihood Explanation

**Likelihood: Low.**

Exploiting this requires a peer to deliberately craft a batch with two votes sharing the same `PerasVoteId`. This is trivially easy to construct but requires the attacker to control a node participating in the Peras vote-diffusion protocol. Honest peers would never send such batches.

---

### Recommendation

Before calling `mapM validateVote`, add an intra-batch deduplication check that detects any two votes in the batch sharing the same `PerasVoteId`. If duplicates are found, treat the batch as invalid and throw `PerasVoteInboundException` (triggering peer disconnection), consistent with the existing policy for any other validation failure. Concretely, after computing `votesNotAlreadyInDb`, verify that all `getPerasVoteId` values in that list are distinct; if not, raise the exception.

---

### Proof of Concept

1. Attacker controls a peer node participating in the Peras object-diffusion mini-protocol.
2. Attacker constructs a batch: `[vote1, vote2]` where both have `pvVoteRound = R`, `pvVoteVoterId = X`, but `pvVoteBlock = A` and `pvVoteBlock = B` respectively.
3. `processVotes` is called. Inside `atomically`, `alreadyInDb` does not contain `(R, X)`. Both votes survive the filter. Both are validated (both pass `lookupPerasVoteStake`). The STM transaction commits.
4. `addVote (WithArrivalTime now validatedVote1)` is called. `implAddVote` finds `(R, X)` absent from `pvdsVoteIds`, inserts it, and returns `AddedPerasVoteButDidntGenerateNewCert` (or cert if quorum reached).
5. `addVote (WithArrivalTime now validatedVote2)` is called. `implAddVote` finds `(R, X)` already in `pvdsVoteIds` and returns `PerasVoteAlreadyInDB` silently.
6. `partitionEithers validationResults` has no `Left` entries, so no exception is thrown. The peer is not disconnected.
7. The attacker has equivocated (voted for two blocks in the same round) without any protocol-level punishment.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-169)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L185-189)
```haskell
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L188-193)
```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-200)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)
```
