### Title
Peras `PerasVoteId` Omits Block Target, Enabling Crafted-Vote Suppression of Legitimate Votes — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs`)

---

### Summary

`PerasVoteId` is keyed only on `(roundNo, voterId)` and does not include the voted block target. The inbound vote pipeline in `processVotes` uses this coarse ID to skip "already-seen" votes **before** any cryptographic validation. Because `validatePerasVote` is a stub that checks only stake-distribution membership (no signature), an unprivileged peer can send a crafted vote for any voter and any block. If that crafted vote arrives before the legitimate vote from the same voter in the same round, the legitimate vote is silently dropped. This is the direct structural analog to the NFT tokenId-tracking failure: the system records *that* a voter voted in a round, but not *which specific block* they voted for, so a crafted entry for the wrong block permanently occupies the slot.

---

### Finding Description

**`PerasVoteId` definition — missing block target**

`PerasVoteId` contains only `pviRoundNo` and `pviVoterId`; the voted block (`pvVoteBlock`) is absent:

```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
``` [1](#0-0) 

The full vote carries a block target (`pvVoteBlock`) that is never part of the deduplication key:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [2](#0-1) 

**`processVotes` — pre-validation filter uses the coarse ID**

The inbound vote handler filters votes by `getPerasVoteId` (i.e., `(round, voter)`) *before* calling `validateVote`:

```haskell
let votesNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
mapM validateVote votesNotAlreadyInDb
``` [3](#0-2) 

Any vote whose `(round, voter)` pair is already in `pvdsVoteIds` is silently skipped — no equivocation check, no peer disconnection.

**`implAddVote` — deduplication gate uses the same coarse ID**

Inside the DB itself, the same coarse check is the sole guard:

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
``` [4](#0-3) 

**`validatePerasVote` — stub with no signature check**

The current production implementation of vote validation only looks up the voter in the stake distribution; there is no cryptographic signature verification:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote{vpvVote = vote, vpvVoteStake = stake}
  | otherwise =
      Left PerasValidationErr
``` [5](#0-4) 

The `PerasVote` type carries no signature field at all, and the TODO at line 172 of `Impl.hs` explicitly acknowledges that non-trivial validation is missing:

```
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [6](#0-5) 

**The model explicitly documents the assumption that is violated**

The reference model acknowledges the fragility:

```
-- NOTE: this is under the assumption that a voter doesn't cast two different
-- votes for the same round (that is, with the same ID but different body).
``` [7](#0-6) 

Because `validatePerasVote` does not enforce this assumption cryptographically, any peer can violate it.

---

### Impact Explanation

An unprivileged peer that sends a crafted `PerasVote{round=R, voter=V, block=B_bad}` before the legitimate vote `{round=R, voter=V, block=B_good}` causes:

1. The crafted vote to pass stub validation (V is in the stake distribution).
2. `(R, V)` to be inserted into `pvdsVoteIds` and `pvdsRoundVoteStates` under target `B_bad`.
3. The legitimate vote to be silently dropped by the `Set.member` guard.

If the attacker repeats this for enough committee members, quorum for `B_good` is never reached, or quorum for `B_bad` is reached instead. This produces a `ValidatedPerasCert` boosting the wrong block, directly corrupting Peras chain-selection weight and potentially causing honest nodes to prefer a non-canonical chain. This maps to the **High** impact class: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain*, and to the **Critical** class: *bypass of certificate validation that enables unauthorized certificate acceptance*.

---

### Likelihood Explanation

**High.** The attack requires only network access to a node that accepts Peras votes via the object-diffusion mini-protocol. No key material, no stake, no special privileges are needed. The attacker only needs to know which voters are in the current committee (derivable from the public stake distribution) and to send crafted votes before the legitimate ones arrive — a straightforward race that is trivially winnable by a well-connected adversary or by a peer that is topologically closer to the target node than the legitimate voters.

---

### Recommendation

1. **Include the block target in `PerasVoteId`**, or maintain a separate per-`(round, voter)` equivocation index that stores the block target and rejects votes for a different block with an explicit error (not a silent drop).
2. **Implement cryptographic signature validation** in `validatePerasVote` before the deduplication gate is applied, so that a crafted vote for voter V cannot pass validation without V's signing key.
3. **Treat equivocating votes as a peer misbehaviour**: when a vote arrives for `(R, V, B2)` and `(R, V, B1)` is already stored (`B1 ≠ B2`), disconnect from the sending peer rather than silently dropping the vote.

---

### Proof of Concept

```
Setup: Round R is active. Voter V (stake weight W) is in the committee.
       Node N has no votes for round R yet.

Step 1 — Attacker sends crafted vote to node N:
  PerasVote { pvVoteRound = R, pvVoteBlock = B_bad, pvVoteVoterId = V }

Step 2 — processVotes (ObjectPool/PerasVote.hs:181):
  alreadyInDb = {}   →   (R,V) not in alreadyInDb   →   vote NOT filtered

Step 3 — validatePerasVote (SupportsPeras.hs:363):
  lookupPerasVoteStake: V ∈ stakeDistr   →   Right (ValidatedPerasVote stake=W)
  (No signature check; PerasVote carries no signature field)

Step 4 — implAddVote (Impl.hs:194):
  (R,V) not in pvdsVoteIds   →   tryAddVote
  pvdsVoteIds  ← insert (R,V)
  pvdsRoundVoteStates ← vote for B_bad from V with stake W

Step 5 — Legitimate vote arrives from voter V:
  PerasVote { pvVoteRound = R, pvVoteBlock = B_good, pvVoteVoterId = V }

Step 6 — processVotes (ObjectPool/PerasVote.hs:181):
  alreadyInDb = {(R,V)}   →   (R,V) ∈ alreadyInDb   →   vote SILENTLY DROPPED

Result: Node N holds a vote for B_bad from V, not B_good.
        Stake W is counted toward B_bad's quorum, not B_good's.
        If repeated for a quorum of committee members, a certificate
        for B_bad is forged; B_good never reaches quorum.
``` [8](#0-7) [9](#0-8) [1](#0-0)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L188-193)
```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L331-336)
```haskell
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-200)
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
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasVoteDB/Model.hs (L151-152)
```haskell
  -- NOTE: this is under the assumption that a voter doesn't cast two different
  -- votes for the same round (that is, with the same ID but different body).
```
