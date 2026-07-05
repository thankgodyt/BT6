### Title
Missing Committee Membership and Signature Validation in Peras Vote Acceptance Path - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production inbound-vote handler (`processVotes`) calls a degenerate `validatePerasVote` implementation that performs **no cryptographic signature check and no committee-eligibility check**. Any unprivileged peer can craft `PerasVote` messages using publicly-known pool IDs from the stake distribution, for any round number and any target block, and those votes will be accepted, aggregated, and — once enough are accumulated — used to forge a Peras certificate that boosts an adversary-chosen block's weight in chain selection.

---

### Finding Description

The vulnerability class from the reference report is **missing capacity/limit enforcement**: a function that creates new items (`_assignNewTokenId`) skips the `maxNumberOfKeys` guard, so more items than intended are minted. The direct analog here is that the function that accepts new votes (`validatePerasVote`) skips the committee-membership and signature guards, so votes from ineligible or unauthenticated parties are accepted and counted toward quorum.

**Root cause — degenerate `validatePerasVote` instance:**

The `BlockSupportsPeras` instance used throughout the production diffusion path is a placeholder that ignores the `PerasCfg` parameter entirely and only checks whether the voter ID appears in the stake distribution:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [1](#0-0) 

The checks that are absent:
- No BLS/KES/VRF signature verification on the vote body
- No committee-eligibility check (VRF-based local sortition, persistent/non-persistent seat assignment)
- No round-number validity check (is this vote for the current or a future round?)
- No target-block validity check

**Production call site — `processVotes`:**

The inbound vote handler for the Peras vote diffusion mini-protocol calls this degenerate validator directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [2](#0-1) 

`processVotes` then adds every vote that passes this trivial check to the `PerasVoteDB` via `addVote`: [3](#0-2) 

**`implAddVote` also carries an explicit TODO acknowledging the missing validation:**

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ...
``` [4](#0-3) 

**Quorum and certificate forging path:**

Once enough accepted votes accumulate for a target, `updatePerasRoundVoteStates` calls `votesReachQuorum` and then `forgePerasCert`, producing a `ValidatedPerasCert` that is stored and used to boost the target block's weight in chain selection: [5](#0-4) 

The `forgePerasCert` degenerate instance also carries the same TODO and unconditionally returns a certificate: [6](#0-5) 

**The correct implementation exists but is not wired into the production path:**

`implVerifyVote` in `WFALS.hs` performs full committee-membership and cryptographic verification, but it is only exercised in unit tests, not in the production `processVotes` → `validatePerasVote` call chain: [7](#0-6) 

---

### Impact Explanation

A forged Peras certificate boosts the weight of the adversary's chosen block by `perasWeight` (a protocol parameter). Because chain selection in Peras is weight-based rather than purely length-based, a certificate-boosted adversary block can be preferred over a longer honest chain. This constitutes:

- **Bypass of Peras voting/certificate checks** enabling unauthorized certificate acceptance (Critical per scope).
- **Chain-selection manipulation** causing an honest node to prefer a non-canonical chain (High per scope).

The `SecurityParam` (`k`) is defined in terms of total weight, so a certificate boost can effectively shrink the rollback budget and cause the adversary's block to become immutable prematurely: [8](#0-7) 

---

### Likelihood Explanation

- Pool IDs are **publicly visible** on-chain; an attacker needs no secret material to construct a `PerasVote` that passes the current check.
- The quorum threshold is a fraction of total stake. An attacker who controls or knows the IDs of pools representing enough stake to exceed the threshold can craft a sufficient number of votes in a single batch.
- The attack requires only a network connection to a node running the Peras vote diffusion mini-protocol — no privileged access, no key compromise.
- The Peras vote diffusion protocol is explicitly designed to accept votes from any connected peer.

---

### Recommendation

Replace the degenerate `validatePerasVote` placeholder with a call to the full committee-verification logic already implemented in `implVerifyVote` (`WFALS.hs`). Specifically:

1. Wire `implVerifyVote` (or an equivalent) into the `processVotes` call site in `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB`.
2. Add round-number validity checks in `implAddVote` (reject votes for rounds that are too old or too far in the future relative to the current slot).
3. Resolve the tracked issue https://github.com/tweag/cardano-peras/issues/120 before the Peras vote diffusion mini-protocol is enabled on any network that enforces Peras chain-selection weight.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → Peras vote diffusion mini-protocol
     → processVotes (ObjectPool/PerasVote.hs:178)
         → validatePerasVote mkPerasParams sd vote   ← only checks stake distr membership
         → addVote (PerasVoteDB/Impl.hs:183)
             → implAddVote
                 → updatePerasRoundVoteStates
                     → votesReachQuorum              ← quorum reached with forged votes
                         → forgePerasCert            ← certificate forged unconditionally
                             → chain selection uses boosted weight
```

**Concrete steps:**

1. Observe the public stake distribution to enumerate pool IDs and their stake weights.
2. Identify a set of pool IDs whose combined stake exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
3. For each pool ID, construct a `PerasVote { pvVoteRound = r, pvVoteBlock = adversaryBlock, pvVoteVoterId = poolId }` for any desired round `r` and any desired target block.
4. Send the batch to a target node via the vote diffusion mini-protocol.
5. `processVotes` calls `validatePerasVote`, which returns `Right` for each vote because each pool ID is present in the stake distribution — no signature or committee check is performed.
6. `implAddVote` stores each vote; `updatePerasRoundVoteStates` accumulates stake; `votesReachQuorum` triggers `forgePerasCert`.
7. The resulting `ValidatedPerasCert` boosts `adversaryBlock` by `perasWeight` in chain selection, potentially causing the node to prefer the adversary's chain over the honest chain. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L373-385)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L571-587)
```haskell
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Candidate ->
  Either
    (PerasForgeErr blk)
    (PerasVoteStateCandidateOrWinner blk)
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-38)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
```
