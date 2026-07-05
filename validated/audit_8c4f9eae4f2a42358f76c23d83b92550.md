### Title
Peras Vote Verification Bypass: `validatePerasVote` Accepts Forged Votes Without Cryptographic Proof - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasVote` implementation accepts any inbound Peras vote whose `pvVoteVoterId` appears in the stake distribution, without verifying any cryptographic signature. The `PerasVote blk` data type carries no signature field at all. An unprivileged peer can therefore forge votes on behalf of any registered stake pool, causing a node to accumulate fraudulent votes, produce a fraudulent Peras certificate, and apply an unearned chain-weight boost to a non-canonical chain.

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasVote` as the gate that must be passed before a peer-submitted vote is stored and counted toward quorum. The production default instance (the only instance in the repository) implements this gate as a pure stake-distribution lookup:

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

The `PerasVote blk` data type carries only a round number, a target block point, and a voter ID — no signature field exists:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [2](#0-1) 

The lookup helper resolves only the voter ID against the distribution map:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [3](#0-2) 

This `validatePerasVote` is the callback wired directly into `processVotes`, the function that handles every batch of inbound votes received from a remote peer:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

`processVotes` adds every vote that passes this check to the vote pool (via `ChainDB.addPerasVoteWithAsyncCertHandling`), and the ChainDB subsequently checks whether accumulated votes reach quorum to forge a certificate: [5](#0-4) 

The `validatePerasCert` path has the same defect — it unconditionally accepts any certificate:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [6](#0-5) 

By contrast, the abstract committee implementations (`EveryoneVotes`, `WFALS`) that are intended to back Peras in production do perform full cryptographic verification — signature check plus VRF eligibility proof — before accepting a vote: [7](#0-6) 

The default instance is explicitly marked as a placeholder (`-- TODO: degenerate instance for all blks to get things to compile`), but it is the only `BlockSupportsPeras` instance present in the repository and is therefore the instance active on any block type, including Cardano blocks, in the current codebase. [8](#0-7) 

### Impact Explanation

An unprivileged remote peer can craft a `PerasVote` message with an arbitrary `pvVoteVoterId` belonging to any registered stake pool. Because `validatePerasVote` performs no cryptographic check, the vote passes validation and is stored. By submitting enough such forged votes targeting the same `(round, block)` pair, the attacker can cause the node to reach the quorum threshold and forge a `ValidatedPerasCert`. That certificate carries a `perasWeight` boost applied during chain selection: [9](#0-8) 

A node that accepts a fraudulent certificate will assign extra weight to the attacker's chosen block, potentially causing it to prefer a non-canonical or adversarially-controlled chain over the honest chain. This is a **bypass of Peras vote/certificate verification** enabling unauthorized chain-weight manipulation — matching the "High" impact tier: bypass of Peras voting checks that enables unauthorized certificate acceptance and chain selection divergence.

### Likelihood Explanation

The attack requires only the ability to send well-formed `PerasVote` network messages to a target node, which is available to any peer connected via the ObjectDiffusion mini-protocol. No keys, stake, or privileged access are needed. The attacker only needs to know which voter IDs are in the current stake distribution (public information) and the target block point. The `processVotes` entry point is reachable from any NTN peer connection.

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (analogous to `VoteSignature` in the `WFALS`/`EveryoneVotes` committee types).
2. Implement `validatePerasVote` to verify that signature against the voter's registered verification key before accepting the vote.
3. Similarly, implement `validatePerasCert` to verify the aggregate certificate signature.
4. Until a production-ready implementation is available, gate the Peras vote ingest path so that it is disabled (or rejects all votes) rather than accepting unauthenticated votes.

### Proof of Concept

1. Connect to a target node as a peer via the ObjectDiffusion mini-protocol.
2. Obtain the current `PerasVoteStakeDistr` (public, derivable from the ledger state).
3. For each registered `PerasVoterId` with sufficient stake, send a `PerasVote` message:
   ```
   PerasVote { pvVoteRound = <target_round>
             , pvVoteBlock = <attacker_chosen_block_point>
             , pvVoteVoterId = <any_registered_pool_id> }
   ```
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; since `pvVoteVoterId` is in the distribution, the vote is accepted and stored via `ChainDB.addPerasVoteWithAsyncCertHandling`.
5. Once accumulated votes exceed the quorum threshold (`stakeAboveThreshold`), the ChainDB forges a `ValidatedPerasCert` for the attacker's chosen block.
6. Chain selection applies the `perasWeight` boost to that block, causing the node to prefer the attacker's chain over the honest chain. [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-270)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-152)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-392)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
        let numSeats =
              localSortitionNumSeats
                (nonPersistentCommitteeSize committee)
                (totalNonPersistentStake committee)
                voterStake
                (normalizeVRFOutput vrfOutput)
        case nonZero numSeats of
          Nothing ->
            Left (ZeroNonPersistentSeats seatIndex)
          Just nonZeroNumSeats ->
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
```
