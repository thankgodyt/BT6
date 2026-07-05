### Title
Incomplete `validatePerasVote` Skips Cryptographic Signature and Eligibility Verification, Allowing Unauthorized Vote Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function in `SupportsPeras.hs` is a stub that only checks whether the claimed voter has stake in the distribution. It does not verify the vote's cryptographic signature, the VRF eligibility proof, or committee membership. An unprivileged peer can submit crafted `PerasVote` objects claiming to be from any pool with positive stake, and those votes will be accepted as `ValidatedPerasVote` without any ownership check. This is a direct analog to the `placeMagnet` bug: just as a player could place a magnet on a planet they do not own by passing an arbitrary `_empire` parameter, an attacker can cast votes on behalf of pools they do not control by sending a vote with an arbitrary `pvVoteVoterId`.

---

### Finding Description

`validatePerasVote` is the sole validation gate before a received vote is stored in the `PerasVoteDB` and counted toward quorum. Its current implementation is:

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
``` [1](#0-0) 

The `_params` argument (which carries the `PerasCfg` needed for committee-scheme-specific checks) is explicitly discarded. The only check performed is `lookupPerasVoteStake vote stakeDistr` — i.e., "does the voter ID appear in the stake distribution with positive stake?" No cryptographic signature over the vote payload is verified, and no VRF eligibility proof is checked.

The `implAddVote` function in `PerasVoteDB.Impl` carries the same TODO, confirming that non-trivial validation has not yet been wired in:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
``` [2](#0-1) 

The full validation pipeline that *should* be applied is implemented in `WFALS.implVerifyVote` and `EveryoneVotes.implVerifyVote`, which verify the vote signature against the public key registered for the claimed seat index, and additionally verify the VRF eligibility proof for non-persistent members: [3](#0-2) [4](#0-3) 

None of these checks are invoked from `validatePerasVote`.

---

### Impact Explanation

**Critical.** Bypass of vote/certificate verification that enables unauthorized vote acceptance.

Because `validatePerasVote` accepts any vote whose claimed voter ID has positive stake, an attacker can:

1. Enumerate all pools with positive stake from the public ledger state.
2. Craft `PerasVote` objects claiming to be from those pools, targeting any block of their choice.
3. Submit the crafted votes via the object diffusion mini-protocol (`processVotes`).
4. Once the accumulated fake stake exceeds the quorum threshold, `updateCandidateVoteState` forges a `ValidatedPerasCert` for the attacker-chosen block. [5](#0-4) 

The forged certificate boosts the attacker's chosen block in chain selection, constituting a consensus safety failure: an honest node is made to prefer a non-canonical or attacker-controlled chain without any legitimate stake backing.

---

### Likelihood Explanation

**High.** The entry point is the public object diffusion mini-protocol, reachable by any unprivileged peer. The attack requires only knowledge of the current stake distribution (public on-chain data) and the ability to send well-formed CBOR-encoded `PerasVote` messages. No key material, admin access, or stake majority is needed. The `processVotes` function explicitly calls `validateVote` on every inbound batch and disconnects peers only on validation failure — but since `validatePerasVote` accepts any vote with a known voter ID, no disconnection occurs. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasVote` with a call to the appropriate committee-scheme's `verifyVote` (i.e., `implVerifyVote` for `WFALS` or `EveryoneVotes`). Concretely:

1. Use `_params` (currently discarded) to obtain the `VotingCommittee` for the current epoch.
2. Convert the concrete `PerasVote` to the committee's `Vote` type via `fromPerasVote`.
3. Call `verifyVote committee vote` and propagate any `VotingCommitteeError` as a `PerasValidationErr`.
4. Only on `Right witness` should the vote be wrapped in `ValidatedPerasVote` and stored.

This mirrors the complete validation already implemented in `WFALS.implVerifyVote`, which checks the vote signature and VRF eligibility proof before returning an `EligibilityWitness`. [7](#0-6) 

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → object diffusion mini-protocol
     → processVotes (PerasVote.hs:178)
     → validateVote (calls validatePerasVote)
     → validatePerasVote: only checks lookupPerasVoteStake
     → ValidatedPerasVote accepted
     → implAddVote → updatePerasRoundVoteStates
     → updateCandidateVoteState → forgePerasCert (quorum reached)
     → certificate stored, boosts attacker-chosen block
```

**Crafted vote structure** (from `PerasVote` CBOR schema):

```
PerasVote {
  pvVoteRound    = <current round>,
  pvVoteBlock    = <attacker-chosen block hash>,
  pvVoteVoterId  = <any PoolId with positive stake, from public ledger>
}
```

No signature field is present in the abstract `PerasVote blk` type used by `validatePerasVote`, and none is checked. Sending N such votes — one per pool with sufficient combined stake — causes `votesReachQuorum` to return `Just votesWithQuorum`, triggering `forgePerasCert` for the attacker's target block. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L361-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L326-390)
```haskell
-- | Verify a vote cast by a committee member in a given election
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L211-232)
```haskell
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
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
