### Title
Peras Vote Replay After Garbage Collection Bypasses Deduplication, Enabling Forged Certificate Injection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs`)

---

### Summary

`implGarbageCollect` permanently erases vote IDs from `pvdsVoteIds` and round-vote states from `pvdsRoundVoteStates`. After GC, the deduplication guard in `processVotes` (which filters on `pvdsVoteIds`) no longer recognises those votes as seen. Because `validatePerasVote` in the current production instance performs no cryptographic signature check, an unprivileged peer can immediately re-submit (or freshly forge) votes for any GC'd round targeting a volatile block, accumulate quorum, and inject a `ValidatedPerasCert` that boosts an attacker-chosen block in chain selection.

---

### Finding Description

**Step 1 — Deduplication relies solely on `pvdsVoteIds`.**

`processVotes` filters inbound votes in a single STM snapshot:

```haskell
validationResults <- atomically $ do
  alreadyInDb <- alreadyInDbSTM          -- reads pvdsVoteIds
  let votesNotAlreadyInDb =
        filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
  mapM validateVote votesNotAlreadyInDb
``` [1](#0-0) 

`implAddVote` repeats the same check inside its own STM transaction, so the only persistent record that a vote was ever accepted is the presence of its `PerasVoteId` in `pvdsVoteIds`. [2](#0-1) 

**Step 2 — `implGarbageCollect` deletes those IDs unconditionally.**

When the immutable tip advances past a round's target slots, GC removes the round from `pvdsRoundVoteStates` and deletes every corresponding ID from `pvdsVoteIds`:

```haskell
pvsVoteIds' =
  Foldable.foldl'
    (\set vote -> Set.delete (getPerasVoteId vote) set)
    pvdsVoteIds
    votesToRemove
``` [3](#0-2) 

No "tombstone" or separate "already-processed-rounds" set is maintained. After GC the DB has no memory that those votes ever existed. [4](#0-3) 

**Step 3 — `validatePerasVote` performs no signature verification.**

The production default instance (used for all `StandardHash blk` blocks, including the current Cardano block type until a proper override is provided) only checks stake-distribution membership:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [5](#0-4) 

Any peer that knows a committee member's public `PerasVoterId` (which is derived from the public stake distribution) can craft a `PerasVote` that passes this check without possessing the corresponding private key.

**Step 4 — Combined attack path.**

The `PerasVote` type carries an arbitrary `pvVoteBlock :: Point blk`: [6](#0-5) 

After GC removes round R's state, an attacker submits forged votes for round R pointing at a *volatile* block B. Because the vote IDs are absent from `pvdsVoteIds`, `processVotes` treats them as new; `validatePerasVote` accepts them; `implAddVote` rebuilds the round state from scratch; and once the attacker's forged votes accumulate enough stake, `updatePerasRoundVoteStates` fires `VoteGeneratedNewCert`, producing a `ValidatedPerasCert` that boosts B. [7](#0-6) 

`addPerasVoteWithAsyncCertHandling` then enqueues the certificate for chain selection: [8](#0-7) 

The `PerasCertIgnoredTooOld` guard only fires when the *boosted block* is already immutable. Because the attacker chose a volatile target, the certificate is processed and B receives a weight boost, potentially causing the node to switch to the attacker's fork. [9](#0-8) 

---

### Impact Explanation

**High.** An unprivileged peer can inject a `ValidatedPerasCert` for an attacker-chosen volatile block by replaying votes into a GC-cleared round. The certificate is accepted by chain selection and boosts the target block's weight, potentially causing an honest node to switch to a non-canonical fork. This matches the "chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" criterion.

---

### Likelihood Explanation

**Medium.** The attacker needs only:
1. A peer connection to the target node (no stake, no keys).
2. Knowledge of committee member `PerasVoterId` values — derived from the public stake distribution.
3. To wait for at least one Peras round to be garbage-collected, which happens automatically as the immutable tip advances.

No key compromise, no majority stake, and no admin access are required.

---

### Recommendation

1. **Maintain a GC-safe "seen rounds" set.** After GC, preserve the set of round numbers (or a compact Bloom filter) for which a certificate was already forged or quorum was reached. Reject any inbound vote whose round number appears in this set, regardless of whether the individual vote ID is still in `pvdsVoteIds`.

2. **Implement cryptographic signature verification in `validatePerasVote`.** The current stub (tracked in issue #120) must be replaced before Peras is active on any network. Until then, any peer can impersonate any committee member.

3. **Make the deduplication check and the `addVote` call atomic.** The TOCTOU window between the STM snapshot in `processVotes` and the subsequent `addVote` calls is currently harmless only because `implAddVote` re-checks; but this layered defence should be made explicit and documented.

---

### Proof of Concept

```
1. Node N has processed round R votes targeting immutable block B_old.
   pvdsVoteIds = { (R, voter1), (R, voter2), ... }
   pvdsRoundVoteStates = { R -> RoundVoteState{...} }

2. Immutable tip advances past B_old's slot.
   Background thread calls garbageCollectPeras(immutableSlot).
   implGarbageCollect removes round R:
     pvdsVoteIds = {}   (all R entries deleted)
     pvdsRoundVoteStates = {}

3. Attacker peer crafts PerasVote { pvVoteRound = R,
                                     pvVoteBlock = B_volatile,  -- attacker's fork tip
                                     pvVoteVoterId = voter_i }
   for enough voter_i values to exceed the quorum threshold.
   No private keys needed; validatePerasVote only checks
   lookupPerasVoteStake, which succeeds for any known voter ID.

4. Attacker sends the batch via the ObjectDiffusion mini-protocol.
   processVotes:
     alreadyInDb = {}  (pvdsVoteIds is empty for round R)
     votesNotAlreadyInDb = all attacker votes
     validateVote succeeds for each (stake-distribution check only)
     addVote called for each

5. implAddVote accumulates votes in pvdsRoundVoteStates[R].
   Once stake threshold crossed:
     AddedPerasVoteAndGeneratedNewCert cert_R_B_volatile

6. addPerasVoteWithAsyncCertHandling enqueues cert_R_B_volatile
   for chain selection. B_volatile is not immutable, so
   PerasCertIgnoredTooOld does NOT fire.
   B_volatile receives perasWeight boost.
   If the attacker's fork is now heavier, N switches chains.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-246)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L279-335)
```haskell
implGarbageCollect ::
  forall m blk.
  IOLike m =>
  PerasVoteDbEnv m blk ->
  SlotNo ->
  STM m (m ())
implGarbageCollect PerasVoteDbEnv{pvdeTracer, pvdeState} slotNo = do
  -- No need to update the 'Fingerprint' as we only remove votes that do
  -- not matter for comparing interesting chains.
  modifyTVar pvdeState (fmap gc)
  pure $ do
    traceWith pvdeTracer (GarbageCollected slotNo)
    return ()
 where
  gc :: PerasVoteDbState blk -> PerasVoteDbState blk
  gc
    PerasVoteDbState
      { pvdsVoteIds
      , pvdsRoundVoteStates
      , pvdsVotesByTicket
      , pvdsLastTicketNo
      } =
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
        deletedRoundNos =
          Map.keysSet roundsToDelete
        -- Then, remove all votes belonging to deleted rounds from the
        -- by-ticket index
        (pvsVotesByTicket', votesToRemove) =
          Map.partition
            (\vote -> not (Set.member (getPerasVoteRound vote) deletedRoundNos))
            pvdsVotesByTicket
        -- Finally, remove the corresponding ids from the set of vote ids
        pvsVoteIds' =
          Foldable.foldl'
            (\set vote -> Set.delete (getPerasVoteId vote) set)
            pvdsVoteIds
            votesToRemove
       in
        PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvdsLastTicketNo
          }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L604-613)
```haskell
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
```
