### Title
Peras Vote Forgery via Missing Cryptographic Signature Verification in `validatePerasVote` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras vote ingestion pipeline (`makePerasVotePoolWriterFromChainDB`) calls `validatePerasVote` using the degenerate `BlockSupportsPeras` instance, which performs **no cryptographic signature check**. The `PerasVote blk` data type carries no signature field, and the validation only checks whether the claimed voter ID appears in the stake distribution. Any unprivileged peer can therefore forge a vote for any eligible voter, directing that voter's stake toward an attacker-chosen block. Because the `PerasVoteDB` deduplicates by `(roundNo, voterId)`, the legitimate vote from the impersonated voter is subsequently rejected as a duplicate, permanently suppressing it for that round.

---

### Finding Description

The `PerasVote blk` data type in the degenerate `BlockSupportsPeras` instance contains only three fields — `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — with no cryptographic signature: [1](#0-0) 

The `validatePerasVote` implementation for this instance only looks up the voter ID in the stake distribution and returns the associated stake; it performs no signature or eligibility-proof verification: [2](#0-1) 

The production vote ingestion function `makePerasVotePoolWriterFromChainDB` (explicitly documented as the correct production path) calls `validatePerasVote mkPerasParams sd vote`, which resolves to this degenerate instance: [3](#0-2) 

The `processVotes` function filters out already-known vote IDs, then validates and stores the remainder. A forged vote that passes the stake-distribution lookup is accepted and stored: [4](#0-3) 

The `PerasVoteId` used for deduplication is `(roundNo, voterId)` — it does not include the target block: [5](#0-4) 

Once a forged vote with ID `(R, X)` is stored, `implAddVote` silently discards any subsequent vote with the same ID, including the legitimate one from voter X: [6](#0-5) 

The WFALS committee implementation does have proper BLS signature and VRF verification in `implVerifyVote`: [7](#0-6) 

However, this path is never invoked by `processVotes`; the `Committee.Class` interface and the `BlockSupportsPeras.validatePerasVote` interface are entirely separate, and only the latter is wired into the network ingestion pipeline.

The TODO comment on the degenerate instance acknowledges the incompleteness: [8](#0-7) [9](#0-8) 

---

### Impact Explanation

An attacker who can connect as a peer and send `PerasVote` objects via the ObjectDiffusion mini-protocol can:

1. **Impersonate any eligible voter** in any round by constructing a `PerasVote` with the target voter's `pvVoteVoterId` and an attacker-chosen `pvVoteBlock`.
2. **Suppress the legitimate vote** from that voter: once the forged vote is stored under `(roundNo, voterId)`, the real vote is rejected as `PerasVoteAlreadyInDB`.
3. **Redirect stake toward an attacker-chosen block**: the forged vote's stake weight is counted toward the attacker's target, potentially causing quorum for a block the legitimate voter never endorsed.
4. **Prevent quorum for the correct block**: by front-running enough eligible voters with votes for a different block, the attacker can prevent the honest block from accumulating sufficient stake.

This constitutes a bypass of Peras voting/certificate checks enabling unauthorized vote acceptance, which can cause the node to forge and propagate a certificate for an attacker-chosen block — a consensus safety failure.

---

### Likelihood Explanation

The attack requires only network connectivity to a target node. The stake distribution is public, so the attacker can enumerate all eligible voters for any round. The `PerasVote` type is serializable and trivially constructable. No key material, stake, or privileged access is required. The only constraint is timing: the forged vote must arrive before the legitimate one, which is straightforward given that the attacker controls when it sends the forged vote and can do so at the start of each voting round.

---

### Recommendation

1. **Add a cryptographic signature field to `PerasVote blk`** (analogous to `WFALSPersistentVote`/`WFALSNonPersistentVote` in the WFALS committee) so that a vote is cryptographically bound to the voter's private key.
2. **Wire the WFALS `verifyVote` (or equivalent) into `validatePerasVote`** so that the `processVotes` ingestion path performs a full signature and eligibility-proof check before accepting any vote.
3. **Do not ship the degenerate `BlockSupportsPeras` instance** in any network-connected code path until full validation is implemented. The `makePerasVotePoolWriterFromChainDB` function should not be reachable from peers until `validatePerasVote` performs real cryptographic verification.

---

### Proof of Concept

1. **Enumerate eligible voters**: read the public `PerasVoteStakeDistr` to obtain all `PerasVoterId` values with non-zero stake for the current epoch.
2. **Construct forged votes**: for each target voter `X` and the current round `R`, build `PerasVote { pvVoteRound = R, pvVoteBlock = attacker_block, pvVoteVoterId = X }`. No signing key is needed.
3. **Send to the victim node** via the ObjectDiffusion mini-protocol at the start of round `R`, before the legitimate voters broadcast their votes.
4. **Observe acceptance**: `processVotes` calls `validatePerasVote mkPerasParams sd vote`, which succeeds because `X` is in the stake distribution. The forged vote is stored under `(R, X)`.
5. **Legitimate votes suppressed**: when voter `X` broadcasts its real vote for round `R`, `implAddVote` finds `(R, X)` already present and returns `PerasVoteAlreadyInDB`, discarding it silently.
6. **Certificate forged for attacker's block**: if enough stake is redirected, `updatePerasRoundVoteStates` reaches quorum for `attacker_block` and a `ValidatedPerasCert` is produced and propagated, boosting the attacker's chosen block in chain selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-200)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L327-390)
```haskell
implVerifyVote ::
  forall crypto.
  ( CryptoSupportsVoteSigning crypto
  , CryptoSupportsVRF crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Vote crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (EligibilityWitness crypto WFALS)
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
