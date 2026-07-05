Let me analyze the vulnerability class from the external report and search for analogous issues in the Ouroboros Consensus codebase.

Let me search more specifically for the vulnerability analog - multi-party signing where a single participant can choose which signed artifact to broadcast.

Let me look more closely at the Peras vote validation and the TODO comment about missing validation logic.

Let me look at the `validatePerasVote` default implementation and the `PerasVoteId` definition to confirm the root cause.

### Title
Peras Vote Signature Verification Completely Absent in Production Path — Any Peer Can Forge Votes and Trigger Spurious Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance — the only instance wired into the production object-diffusion path — implements `validatePerasVote` as a pure stake-lookup with no cryptographic check. The abstract `PerasVote blk` type carries no signature field at all. Any unprivileged peer connected via the Peras object-diffusion mini-protocol can therefore craft a structurally valid `PerasVote` for any eligible voter ID and any block hash, have it accepted as `ValidatedPerasVote`, accumulate it in the `PerasVoteDB`, and — if it submits enough such forged votes — trigger automatic certificate forging for an arbitrary block, directly manipulating Peras-weighted chain selection.

---

### Finding Description

**Root cause — abstract type carries no signature**

`PerasVote blk` is defined in the universal instance as:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

There is no signature field. [1](#0-0) 

**Root cause — `validatePerasVote` only checks stake**

The universal instance's `validatePerasVote` performs a single `Map.lookup` on the stake distribution. If the voter ID has any stake, the vote is unconditionally accepted as `ValidatedPerasVote`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

The same issue is acknowledged in `implAddVote`:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [3](#0-2) 

**Attacker-controlled entry path — object diffusion pool writer**

Both production pool writers (`makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`) call `validatePerasVote` directly with the degenerate instance:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) [5](#0-4) 

`processVotes` then adds every vote that passes this check to the DB: [6](#0-5) 

**Deduplication does not protect against cross-voter forgery**

`PerasVoteId` is `(PerasRoundNo, PerasVoterId)`. The DB deduplicates by this pair, so one forged vote per eligible voter per round is accepted. An attacker who submits forged votes for enough distinct eligible voters can accumulate stake above the quorum threshold. [7](#0-6) [8](#0-7) 

**Certificate auto-forging on quorum**

`updatePerasRoundVoteStates` automatically forges a `ValidatedPerasCert` the moment accumulated stake crosses the quorum threshold: [9](#0-8) 

The forged certificate is then propagated to the `ChainDB`, where it boosts the Peras weight of the attacker-chosen block in chain selection.

---

### Impact Explanation

A Peras certificate boosts the `PerasWeight` of the certified block in chain selection. An attacker who causes a certificate to be forged for a minority or adversarial block can make an honest node prefer that block over the honest chain tip, constituting a **chain-selection manipulation** and **bypass of Peras certificate/vote authorization**. This falls squarely within:

> *Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance.*

The concrete `V1.PerasVote` type (used by the committee layer) does carry a BLS signature field, but that layer is never reached in the current production validation path — the degenerate instance intercepts all votes first. [10](#0-9) 

---

### Likelihood Explanation

The object-diffusion mini-protocol is reachable by any peer that connects to the node. The stake distribution is public (derived from the ledger). An attacker needs only to enumerate eligible voter IDs from the public stake distribution, construct `PerasVote` records with those IDs pointing to an attacker-chosen block, and submit them via the mini-protocol. No key material, operator access, or stake majority is required.

---

### Recommendation

1. **Add a cryptographic signature field to `PerasVote blk`** (or use the concrete `V1.PerasVote` type directly in the validation path) so that `validatePerasVote` can verify the BLS signature before accepting a vote.
2. **Remove the universal `instance StandardHash blk => BlockSupportsPeras blk`** placeholder (tracked in issue #73) and replace it with a concrete instance that performs full validation per issue #120.
3. **Add per-voter equivocation detection** in `implAddVote`: if a vote arrives for a `(roundNo, voterId)` pair already in the DB but with a different `pvVoteBlock`, it should be rejected (or the peer disconnected), not silently ignored.

---

### Proof of Concept

```
Attacker (any connected peer):

1. Read the current PerasVoteStakeDistr from the public ledger state.
   Enumerate all PerasVoterId entries with non-zero stake.

2. For each voterId_i with stake s_i, construct:
     vote_i = PerasVote
       { pvVoteRound   = currentRound
       , pvVoteBlock   = adversarialBlockHash   -- any block hash
       , pvVoteVoterId = voterId_i
       }
   (No signature needed — the abstract type has no signature field.)

3. Send vote_1 … vote_N via the Peras object-diffusion mini-protocol.

4. processVotes calls:
     validatePerasVote mkPerasParams stakeDistr vote_i
   which returns Right (ValidatedPerasVote { vpvVoteStake = s_i })
   for every vote_i whose voterId_i is in the stake distribution.

5. Each validated vote is inserted into PerasVoteDB via implAddVote.
   updatePerasRoundVoteStates accumulates stake.

6. Once sum(s_i) > quorumThreshold, a ValidatedPerasCert is automatically
   forged for adversarialBlockHash and propagated to ChainDB.

7. Chain selection now assigns extra PerasWeight to adversarialBlockHash,
   potentially causing the node to prefer the adversarial chain.
``` [11](#0-10) [12](#0-11) [13](#0-12)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-152)
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
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }

-- | Create a pool writer from the 'ChainDB'.
-- This properly handles the produced certs by letting the ChainDB take care
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```
