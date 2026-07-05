### Title
Peras Vote Signature Verification Bypass Allows Unauthorized Certificate Forging — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` function accepts any inbound vote whose voter ID appears in the stake distribution, without verifying the vote's cryptographic signature. An unprivileged peer can therefore impersonate any committee member, forge votes for an arbitrary block, and — once enough fake stake accumulates — trigger automatic certificate creation that boosts a non-canonical chain in chain selection.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that turns a raw `PerasVote` received from the network into a `ValidatedPerasVote` carrying a trusted stake weight. The only concrete instance in the codebase is the universal `instance StandardHash blk => BlockSupportsPeras blk` at line 320 of `SupportsPeras.hs`. Its implementation is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The only check performed is a `Map.lookup` of the voter's `PerasVoterId` in the local `PerasVoteStakeDistr`. No cryptographic signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)` is verified. The `_params` argument (which carries the `PerasCfg` needed for any protocol-level checks) is explicitly discarded.

Contrast this with the `WFALS` committee implementation, which is the reference implementation of vote verification. `implVerifyVote` for a `WFALSNonPersistentVote` performs:
1. `verifyVoteSignature` — cryptographic signature check
2. `evalVRF` — VRF eligibility proof check
3. `localSortitionNumSeats` / `nonZero` — seat allocation check

The production path skips all three. The same asymmetry exists for `validatePerasCert`, which unconditionally returns `Right` for every certificate it receives.

The validated vote flows directly into the live system. `makePerasVotePoolWriterFromChainDB` calls `processVotes`, which calls `validatePerasVote` inside an STM transaction, and on success passes the `ValidatedPerasVote` to `ChainDB.addPerasVoteWithAsyncCertHandling`. Inside `implAddVote`, `updatePerasRoundVoteStates` accumulates the vote's `vpvVoteStake` and calls `stakeAboveThreshold` to decide whether to forge a certificate. A forged certificate carries a `vpcCertBoost` weight that is applied during chain selection.

### Impact Explanation

An unprivileged peer who knows any `PerasVoterId` present in the current `PerasVoteStakeDistr` (a public value derived from the ledger stake snapshot) can:

1. Craft `PerasVote { pvVoteRound = r, pvVoteBlock = attackerPoint, pvVoteVoterId = victimId }` for any round `r` and any block point `attackerPoint`.
2. Send the vote to a target node. `processVotes` will call `validatePerasVote`, which succeeds because `victimId` is in the distribution.
3. Repeat with different `victimId` values until the accumulated `PerasVoteStake` satisfies `stakeAboveThreshold`.
4. `implAddVote` calls `forgePerasCert`, producing a `ValidatedPerasCert` with `pcCertBoostedBlock = attackerPoint` and a non-zero `vpcCertBoost`.
5. The boosted block is preferred in chain selection over an equally-long honest chain.

This constitutes a **bypass of vote/certificate verification** that lets an unprivileged peer cause an honest node to accept an unauthorized certificate and prefer a non-canonical chain — matching the "Critical: Bypass of certificate/vote verification checks" impact category.

### Likelihood Explanation

The attack requires only knowledge of current committee member key hashes, which are derivable from the public ledger stake distribution. No key material, stake majority, or privileged access is needed. The `makePerasVotePoolWriterFromChainDB` path is wired into the node's miniprotocol diffusion layer and is reachable by any connected peer. Likelihood is **High** once Peras voting rounds are active.

### Recommendation

Replace the stub `validatePerasVote` with a full implementation that:
1. Verifies the cryptographic signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)` using the voter's public key from the committee selection context (not just the stake distribution).
2. Checks that the voter is an eligible committee member for the given round (VRF proof for non-persistent members, persistent-seat check for persistent members), mirroring `implVerifyVote` in `WFALS.hs`.
3. Validates that `pvVoteRound` falls within the current valid voting window.

Similarly, `validatePerasCert` must verify the aggregate BLS signature over the certificate's voter set before returning `Right`.

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → miniprotocol (PerasVote diffusion)
     → makePerasVotePoolWriterFromChainDB          [PerasVote.hs:131]
     → processVotes                                [PerasVote.hs:178]
     → validatePerasVote mkPerasParams sd vote     [PerasVote.hs:141]
         -- only checks Map.lookup pvVoteVoterId sd
         -- no signature verification
     → ChainDB.addPerasVoteWithAsyncCertHandling   [PerasVote.hs:147]
     → implAddVote → updatePerasRoundVoteStates    [Impl.hs:208]
     → stakeAboveThreshold → forgePerasCert        [Aggregation.hs]
     → ValidatedPerasCert with vpcCertBoost        [SupportsPeras.hs:376]
     → chain selection prefers boosted block
```

**Minimal reproducer (private testnet):**

1. Observe the `PerasVoteStakeDistr` for the current epoch (public ledger query).
2. For each `PerasVoterId` with sufficient stake, send `PerasVote { pvVoteRound = currentRound, pvVoteBlock = attackerBlockPoint, pvVoteVoterId = id }` to the target node.
3. Observe that `implAddVote` emits `AddedPerasVoteAndGeneratedNewCert` once accumulated stake exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. Confirm the target node's chain selection now boosts `attackerBlockPoint`.

---

**Relevant citations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-211)
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
