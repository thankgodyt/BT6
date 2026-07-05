### Title
Stub `validatePerasVote` Accepts Forged Votes Without Cryptographic Verification, Enabling Unauthorized Peras Certificate Acceptance — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation only checks that a voter ID exists in the stake distribution. It performs no cryptographic signature verification and no committee-eligibility check. An unprivileged peer can craft `PerasVote` messages with any valid voter ID from the public stake distribution, have them accepted by `processVotes`, and accumulate enough forged stake to trigger a false quorum certificate for an arbitrary block.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that must be passed before a vote is admitted to the `PerasVoteDB`. The sole production instance (the degenerate `instance StandardHash blk => BlockSupportsPeras blk`) implements this gate as:

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

The check is purely a map lookup on the voter ID. No signature over the vote body is verified, and no VRF/committee-eligibility proof is checked. The `_params` argument (which would carry cryptographic configuration) is explicitly discarded.

This stub is called on every inbound vote inside `processVotes`, the sole inbound path for network-received votes:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  ...
  mapM_ (addVote . WithArrivalTime now) validatedVotes
``` [2](#0-1) 

Both production pool writers (`makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`) funnel all peer-supplied votes through this path: [3](#0-2) [4](#0-3) 

Once a vote passes `validatePerasVote`, it is unconditionally inserted into `implAddVote` with its full stake weight, and the aggregation logic in `updatePerasRoundVoteStates` counts it toward quorum: [5](#0-4) 

The duplicate-vote guard (`pvdsVoteIds`) is keyed on `(voterId, roundNo)`, so an attacker can submit one forged vote per voter per round, and each will be counted once with its full stake weight. [6](#0-5) 

The model explicitly acknowledges the assumption that is violated here:

> NOTE: this is under the assumption that a voter doesn't cast two different votes for the same round (that is, with the same ID but different body). [7](#0-6) 

---

### Impact Explanation

When enough forged votes accumulate to exceed the quorum threshold, `updateCandidateVoteState` calls `forgePerasCert` and a `ValidatedPerasCert` is produced for the attacker-chosen block: [8](#0-7) 

This certificate is then propagated to the `ChainDB` and used in chain selection to boost the attacker's block. An honest node receiving this certificate would treat it as a valid Peras finality signal and prefer the boosted chain, constituting an unauthorized certificate acceptance and a potential chain-selection manipulation.

This matches the **Critical** impact category: bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance.

---

### Likelihood Explanation

The stake distribution is public. Any peer connected via the object diffusion mini-protocol can send `PerasVote` messages. The attacker needs only to enumerate voter IDs from the stake distribution and craft votes with those IDs targeting a chosen block. No key material, no stake, and no special network position is required. The attack is executable by any unprivileged peer in a single round of message exchange.

---

### Recommendation

Replace the stub `validatePerasVote` with a real implementation that:
1. Verifies the cryptographic signature on the vote body using the voter's registered key.
2. Verifies committee eligibility (VRF proof or WFALS/EveryoneVotes witness) for the claimed voter in the current round.
3. Rejects votes whose `pvVoteRound` or `pvVoteBlock` fall outside the currently valid window.

Until issue [#120](https://github.com/tweag/cardano-peras/issues/120) is resolved, the object diffusion inbound path should refuse to accept any votes from external peers (i.e., `processVotes` should reject all inbound votes rather than forwarding them through the stub validator).

---

### Proof of Concept

```
Attacker peer A connects to honest node N via the object diffusion mini-protocol.

1. A reads the public stake distribution: voters = {V1 (stake 0.3), V2 (stake 0.3), V3 (stake 0.3)}.
   Quorum threshold = 0.51 of total stake.

2. A crafts three PerasVote messages:
     vote1 = PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock, pvVoteVoterId = V1 }
     vote2 = PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock, pvVoteVoterId = V2 }
     vote3 = PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock, pvVoteVoterId = V3 }
   (No signatures, no VRF proofs — the body is entirely attacker-controlled.)

3. A sends [vote1, vote2, vote3] to N via opwAddObjects.

4. processVotes on N:
   - alreadyInDb = {} (none seen yet)
   - votesNotAlreadyInDb = [vote1, vote2, vote3]
   - validatePerasVote is called for each:
       lookupPerasVoteStake vote1 stakeDistr = Just 0.3  => Right (ValidatedPerasVote stake=0.3)
       lookupPerasVoteStake vote2 stakeDistr = Just 0.3  => Right (ValidatedPerasVote stake=0.3)
       lookupPerasVoteStake vote3 stakeDistr = Just 0.3  => Right (ValidatedPerasVote stake=0.3)
   - All three pass; addVote is called for each.

5. implAddVote inserts all three; updatePerasRoundVoteStates accumulates
   totalStake = 0.9 > 0.51 => quorum reached => forgePerasCert produces cert for attackerBlock.

6. The certificate is propagated to ChainDB; chain selection boosts attackerBlock.
```

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
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
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasVoteDB/Model.hs (L150-153)
```haskell
  --
  -- NOTE: this is under the assumption that a voter doesn't cast two different
  -- votes for the same round (that is, with the same ID but different body).
  | voterAlreadyVotedInRound =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L582-587)
```haskell
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```
