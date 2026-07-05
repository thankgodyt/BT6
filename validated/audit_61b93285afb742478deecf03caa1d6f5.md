### Title
Peras Vote and Certificate Validation Stubs Accept Any Peer-Submitted Vote/Certificate Without Signature Verification — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` default instance ships two stub validation functions: `validatePerasVote` performs no cryptographic signature check and only looks up the voter ID in the stake distribution, while `validatePerasCert` unconditionally returns `Right` for every certificate it receives. Because these stubs are the only `BlockSupportsPeras` instance in the codebase and are wired directly into the live Peras ObjectDiffusion inbound path, any unprivileged peer can submit forged votes claiming to be from any legitimate voter ID, accumulate a quorum, trigger certificate forging, and cause the node to switch chains — all without possessing any signing key.

### Finding Description

**Root cause — `validatePerasVote` stub (no signature field, no signature check):** [1](#0-0) 

The stub `PerasVote blk` data type carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — there is no signature field at all. The `validatePerasVote` implementation ignores `_params` entirely and only calls `lookupPerasVoteStake vote stakeDistr`, a plain `Map.lookup` on the voter ID:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

Any attacker who knows a valid `PerasVoterId` (publicly derivable from the stake distribution) can craft a `PerasVote` for any round and any block point and have it accepted as `ValidatedPerasVote`.

**Root cause — `validatePerasCert` stub (always `Right`):** [2](#0-1) 

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

Every certificate submitted by any peer is unconditionally wrapped in `ValidatedPerasCert` and returned as `Right`. No round-number bounds, no aggregate-signature check, no boosted-block existence check.

**These stubs are the only `BlockSupportsPeras` instance in the codebase:** [3](#0-2) 

The catch-all `instance StandardHash blk => BlockSupportsPeras blk` is the sole instance. No Cardano-specific override exists anywhere in the repository.

**These stubs are called directly in the live inbound ObjectDiffusion path:** [4](#0-3) 

`makePerasVotePoolWriterFromChainDB` — the production writer wired into the node — calls:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

`processVotes` then accepts every vote that passes this stub check and forwards it to `ChainDB.addPerasVoteWithAsyncCertHandling`: [5](#0-4) 

**Certificate forging and chain selection are triggered automatically once quorum is reached:** [6](#0-5) 

`addPerasVoteWithAsyncCertHandling` calls `addPerasCertAsync` when `AddedPerasVoteAndGeneratedNewCert` is returned, which enqueues a chain-selection event. The `votesReachQuorum` function accumulates `vpvVoteStake` values from the stub-validated votes: [7](#0-6) 

**The WFALS/EveryoneVotes committee schemes do perform real cryptographic verification**, but they are not connected to the `BlockSupportsPeras` class and are therefore never invoked on the inbound peer path: [8](#0-7) 

### Impact Explanation

**Critical — Bypass of Peras vote/certificate signature validation enabling unauthorized certificate acceptance and chain selection manipulation.**

An attacker with no privileged access can:

1. Enumerate legitimate `PerasVoterId` values from the public stake distribution.
2. Craft `PerasVote` objects pointing to an attacker-controlled block, with no signature required.
3. Submit enough such votes via the ObjectDiffusion protocol to exceed the quorum threshold (`stakeAboveThreshold`).
4. The node internally forges a `ValidatedPerasCert` for the attacker's block and enqueues it for chain selection.
5. The Peras weight boost causes the node to prefer the attacker's chain over the honest chain.

Alternatively, the attacker can skip the vote path entirely and submit a crafted `PerasCert` directly via the cert diffusion channel; `validatePerasCert` will accept it unconditionally.

This directly satisfies the "Critical — Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance" impact category, and also "High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain."

### Likelihood Explanation

**High.** The attacker needs only a TCP connection to the target node and knowledge of any voter ID present in the current stake distribution (publicly available on-chain). No keys, no stake, no admin access are required. The `PerasVote` struct carries no signature field, so there is nothing to forge cryptographically — the attacker simply constructs a valid Haskell/CBOR-encoded record with a known voter ID and a chosen block point. The ObjectDiffusion inbound handler (`processVotes`) is reachable from any connected peer.

### Recommendation

1. **Immediate**: Gate the Peras ObjectDiffusion inbound handlers behind a feature flag that is disabled until real `validatePerasVote` and `validatePerasCert` implementations are in place.
2. **Short-term**: Replace the stub `BlockSupportsPeras` instance with a type-class method that has no default implementation, forcing every concrete block type to provide a real implementation before the code compiles.
3. **Long-term**: Wire the existing `implVerifyVote` / `implVerifyCert` logic from the `WFALS` and `EveryoneVotes` committee schemes into the `BlockSupportsPeras` class methods for the production Cardano block type, ensuring that every inbound vote and certificate is verified against the committee's cryptographic keys before being admitted to the VoteDB or CertDB.

### Proof of Concept

**Preconditions**: A node with Peras ObjectDiffusion enabled; attacker has a standard peer connection.

**Steps**:

1. Query the current `PerasVoteStakeDistr` (publicly derivable from the ledger state via the local state query protocol). Extract any `PerasVoterId` with sufficient stake.
2. Construct `N` `PerasVote` objects (one per voter ID needed to exceed quorum), each with:
   - `pvVoteRound` = current Peras round
   - `pvVoteBlock` = point of an attacker-controlled block already in the network
   - `pvVoteVoterId` = a legitimate voter ID from step 1
3. Send these votes to the target node via the ObjectDiffusion vote inbound channel.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each; the stub returns `Right` for every vote whose voter ID is in `sd`.
5. `addPerasVoteWithAsyncCertHandling` accumulates stake; once `stakeAboveThreshold` is satisfied, `forgePerasCert` is called and `addPerasCertAsync` enqueues a chain-selection event.
6. Chain selection runs with the Peras weight boost applied to the attacker's block; the node switches to the attacker's chain.

**Expected outcome**: The honest node's selection is replaced by the attacker-designated chain without the attacker possessing any voting key or stake.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-322)
```haskell
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-390)
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
```
