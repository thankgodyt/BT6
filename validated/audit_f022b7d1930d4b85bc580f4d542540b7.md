### Title
Unauthenticated `PerasVoteId` Deduplication Enables Vote-DB Poisoning and Peras Quorum Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The Peras vote diffusion pipeline deduplicates incoming votes by `PerasVoteId = (PerasRoundNo, PerasVoterId)` before invoking `validatePerasVote`. The production default instance of `validatePerasVote` omits all cryptographic signature verification, accepting any vote whose `PerasVoterId` appears in the stake distribution. An unprivileged peer can therefore submit structurally valid but unsigned/forged votes for any registered voter, have them accepted and persisted in the `PerasVoteDB`, and permanently suppress the legitimate votes from those voters for the same round via the deduplication gate. With enough targeted voters, the attacker can prevent honest quorum from forming or steer quorum toward an adversarial boosted block, directly corrupting Peras chain selection.

### Finding Description

**Root cause — missing signature check in `validatePerasVote`:**

The `BlockSupportsPeras` catch-all instance in `SupportsPeras.hs` provides the production implementation of `validatePerasVote` used for all block types:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check performed is whether `pvVoteVoterId` appears in the stake distribution map. No signature, VRF proof, or any other cryptographic binding between the claimed voter identity and the vote content is verified. [1](#0-0) 

**Deduplication key excludes the block target:**

`PerasVoteId` is defined as only `(PerasRoundNo, PerasVoterId)` — it does not include `pvVoteBlock` (the boosted block point):

```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
``` [2](#0-1) 

`getPerasVoteId` extracts exactly this pair from any `PerasVote`: [3](#0-2) 

**Deduplication precedes validation in `processVotes`:**

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb =
          filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

Votes whose `(roundNo, voterId)` pair is already in `pvdsVoteIds` are silently dropped before `validateVote` is ever called. Once a forged vote is accepted and persisted, the legitimate vote from the same voter for the same round is permanently suppressed. [4](#0-3) 

**Persistence in `implAddVote`:**

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
```

Once the forged vote's `PerasVoteId` is inserted into `pvdsVoteIds`, the deduplication gate is permanently closed for that `(roundNo, voterId)` pair for the lifetime of the round. [5](#0-4) 

**Exploit path:**

1. Attacker connects as an ordinary peer and reads the public stake distribution to enumerate registered `PerasVoterId` values.
2. For a target round `R` and an adversarial block `B_adv`, the attacker constructs `PerasVote { pvVoteRound = R, pvVoteBlock = B_adv, pvVoteVoterId = <legitimate voter> }` for each high-stake voter.
3. These votes are sent via the ObjectDiffusion mini-protocol before the legitimate votes arrive.
4. `processVotes` calls `validatePerasVote`: each vote passes because `pvVoteVoterId` is in the stake distribution. The votes are timestamped and added to the `PerasVoteDB`.
5. When the legitimate votes arrive, `processVotes` finds their `PerasVoteId` already in `pvdsVoteIds` and silently drops them.
6. The `PerasVoteDB` now holds forged votes for `B_adv` from the targeted voters. If the attacker covers enough stake, `updatePerasRoundVoteStates` reaches quorum for `B_adv`, forges a `ValidatedPerasCert`, and the Peras boost is applied to the adversarial block in chain selection. [6](#0-5) 

### Impact Explanation

**Critical — Bypass of Peras voting checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

The `validatePerasVote` stub accepts any vote from a registered voter without verifying that the voter actually signed it. An unprivileged peer can:

- **Suppress legitimate votes**: by pre-poisoning the dedup set for targeted `(roundNo, voterId)` pairs, preventing honest quorum from forming for the correct block.
- **Forge quorum for an adversarial block**: by submitting enough forged votes pointing to `B_adv`, triggering `forgePerasCert` for `B_adv`, and causing the Peras boost to be applied to a block the honest voters never endorsed.
- **Corrupt chain selection**: the resulting `ValidatedPerasCert` is used by `preferAnchoredCandidate` / `PerasWeightSnapshot` to boost `B_adv` over the honest chain tip, causing the node to prefer a non-canonical chain.

This falls squarely within: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance"* and *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

**High.** The attack requires only:
- A standard peer connection (no credentials).
- Knowledge of the public stake distribution (available on-chain).
- Sending crafted `PerasVote` messages before legitimate votes arrive — a race that is trivially won by a well-connected adversary or a peer that is the first to connect.

The `PerasVote` wire format is fully specified and serialisable without any secret material. The stub `validatePerasVote` is the active production code path for all block types (the catch-all instance `instance StandardHash blk => BlockSupportsPeras blk`). No operator misconfiguration is required.

### Recommendation

1. **Implement cryptographic vote signature verification in `validatePerasVote`** before the vote is accepted into the DB. The vote must carry a signature over `(roundNo, boostedBlock)` verifiable against the voter's registered key, analogous to how `doValidateKESSignature` verifies the block issuer's identity before updating `ocertCounters`.

2. **Include a cryptographic commitment in `PerasVoteId`** (e.g., a hash of the full signed vote) so that two votes with the same `(roundNo, voterId)` but different content or signatures are not conflated by the deduplication gate.

3. **Invert the order of deduplication and validation**: validate the signature first; only then check for and record the `PerasVoteId`. This prevents an invalid/forged vote from ever occupying a dedup slot.

### Proof of Concept

```haskell
-- Attacker constructs a forged vote for voter V in round R targeting adversarial block B_adv.
-- No signing key for V is needed; validatePerasVote only checks stake distribution membership.

let forgedVote = PerasVote
      { pvVoteRound   = targetRound          -- R
      , pvVoteBlock   = adversarialBlockPoint -- B_adv
      , pvVoteVoterId = legitimateVoterId     -- V (public, from stake distribution)
      }

-- processVotes on the victim node:
--   1. alreadyInDb does NOT contain PerasVoteId{pviRoundNo=R, pviVoterId=V} yet
--   2. validatePerasVote: lookupPerasVoteStake forgedVote stakeDistr = Just stake  => Right
--   3. forgedVote is added to pvdsVoteIds and pvdsVotesByTicket

-- Legitimate vote from V arrives later:
--   1. alreadyInDb NOW contains PerasVoteId{pviRoundNo=R, pviVoterId=V}
--   2. filter drops it silently -- legitimate vote is permanently suppressed

-- If attacker repeats for enough high-stake voters:
--   updatePerasRoundVoteStates reaches quorum for B_adv
--   => forgePerasCert produces ValidatedPerasCert for B_adv
--   => Peras boost applied to adversarial block in chain selection
``` [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L565-570)
```haskell
instance HasPerasVoteId (PerasVote blk) blk where
  getPerasVoteId vote =
    PerasVoteId
      { pviRoundNo = pvVoteRound vote
      , pviVoterId = pvVoteVoterId vote
      }
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
