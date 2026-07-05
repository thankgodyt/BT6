### Title
`implVerifyCert` Does Not Enforce Quorum Threshold on Certificate Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs` and `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs`)

---

### Summary

Both `implVerifyCert` implementations for the `EveryoneVotes` and `WFALS` voting committee schemes verify individual voter eligibility and the aggregate cryptographic signature, but **never check that the total stake of the certified voters meets the quorum threshold**. This is the direct analog of the reported bug: a verification function is missing a mandatory invariant check, allowing a structurally valid but semantically invalid certificate to pass verification. A network peer who is a committee member can craft a certificate with valid individual signatures but sub-quorum total stake; the certificate passes `verifyCert`, and the boosted block gains unearned chain weight, causing chain-selection divergence.

---

### Finding Description

The `VotingCommittee` class defines `verifyCert` as the gate that decides whether a received certificate is legitimate: [1](#0-0) 

The `EveryoneVotes` implementation (`implVerifyCert`) traverses the voter set, checks each seat index is within bounds and has non-zero stake, then verifies the aggregate BLS signature: [2](#0-1) 

The `WFALS` implementation additionally checks persistent/non-persistent membership and batch-verifies VRF outputs: [3](#0-2) 

**Neither implementation sums the stake of the verified voters and compares it against the quorum threshold.** The quorum check (`stakeAboveThreshold`) exists only in the certificate-forging path (`votesReachQuorum` / `updateCandidateVoteState`), which is executed locally when a node accumulates votes: [4](#0-3) [5](#0-4) 

It is never re-applied when a certificate is **received from the network** and verified. The `VotingCommittee` class provides `eligiblePartyVoteWeight` to compute per-voter weight, but no caller of `verifyCert` is required to aggregate these weights and check them against the threshold. [6](#0-5) 

The missing invariant is: **a certificate is only valid if the total stake of its voters exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`**. This invariant is enforced at forge time but not at verify time.

---

### Impact Explanation

A Peras certificate boosts the chain weight of the certified block by `perasWeight` (default: 15 block-equivalents): [7](#0-6) 

An adversary who controls even a single committee seat can construct a `WFALSCert` or `EveryoneVotesCert` containing only their own valid signature. `implVerifyCert` will accept it (individual signature is valid, seat index is in bounds, stake is non-zero). The receiving node applies the boost, making the adversary's chosen block appear heavier than it truly is. Honest nodes following chain selection will prefer this artificially boosted chain, causing divergence from the canonical chain. This satisfies the **High** impact criterion: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The attacker must be a legitimate committee member (hold some stake and have a valid seat index in the current epoch's `ExtWFAStakeDistr`). This is a realistic condition for any active stake pool operator. The attack requires only crafting a certificate with a single valid voter entry and a valid aggregate signature over that single entry — a straightforward operation for anyone who can already forge a legitimate single-voter certificate. The certificate is delivered over the standard Peras network protocol path. No key compromise, admin access, or majority stake is required.

---

### Recommendation

Add a quorum threshold check inside both `implVerifyCert` implementations, after the per-voter eligibility loop and before returning `Right members`. Concretely:

1. After collecting all `EligibilityWitness` values, sum their weights using `eligiblePartyVoteWeight`.
2. Compare the total weight against the committee's quorum threshold.
3. Return a new `VotingCommitteeError` variant (e.g., `InsufficientQuorumStake`) if the threshold is not met.

This mirrors the existing `stakeAboveThreshold` check in `votesReachQuorum` and closes the gap between forge-time and verify-time invariant enforcement. The `VotingCommittee` class interface should also document that `verifyCert` is required to enforce the quorum invariant, not merely the cryptographic validity of individual votes.

---

### Proof of Concept

1. Obtain a valid committee seat (any pool with positive stake in the current epoch).
2. Forge a single `WFALSPersistentVote` or `EveryoneVotesVote` for the target block.
3. Call `forgeCert` on a `UniqueVotesWithSameTarget` containing only that one vote. This succeeds because `forgeCert` only checks that vote signatures are unique and aggregates them — it does not check quorum. [8](#0-7) 

4. Send the resulting `WFALSCert` (one voter, valid aggregate signature, sub-quorum total stake) to an honest node.
5. The honest node calls `verifyCert` → `implVerifyCert`. The seat index is within bounds, the voter is a persistent member, the aggregate signature verifies. `implVerifyCert` returns `Right [WFALSPersistentMember seatIndex voterStake]`.
6. No quorum check is performed. The certificate is accepted and the target block receives a `perasWeight`-unit boost in chain selection. [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L103-107)
```haskell
  -- | Compute the voting weight of a eligibile party
  eligiblePartyVoteWeight ::
    VotingCommittee crypto committee ->
    EligibilityWitness crypto committee ->
    VoteWeight
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L116-122)
```haskell
  -- | Verify a certificate attesting the winner of a given election
  verifyCert ::
    VotingCommittee crypto committee ->
    Cert crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (NE [EligibilityWitness crypto committee])
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L292-340)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  CryptoSupportsAggregateVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Cert crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (NE [EligibilityWitness crypto EveryoneVotes])
implVerifyCert committee = \case
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig

    -- Return the list of voters attesting the election winner
    pure members
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L451-482)
```haskell
        (getElectionIdFromVotes votes)
        (getVoteCandidateFromVotes votes)
        voterMap
        aggSig
 where
  -- We want to fail fast in case if the number of votes is not the same
  -- as voters representation in WFALSCert. This assumption may be
  -- violated in case if implementation uses incorrect ordering function
  -- in the `ensureUniqueVotesWithSameTarget`
  allUniqueVoterSeats =
    NEMap.size voterMap == length voters
      && NEMap.size voterMap == length voteSignatures
  voterMap = NEMap.fromAscList voters
  (voters, voteSignatures) =
    munzip $ flip fmap votesInAscendingSeatIndexOrder $ \case
      WFALSPersistentVote seatIndex _ _ sig ->
        ( (seatIndex, Nothing)
        , sig
        )
      WFALSNonPersistentVote seatIndex _ _ vrfOutput sig ->
        ( (seatIndex, Just vrfOutput)
        , sig
        )

  -- Make sure we have votes in ascending seat index order, which is something
  -- 'VotesWithSameTarget' cannot guarantee by itself, since seat indices are
  -- an implementation detail of this voting committee scheme.
  votesInAscendingSeatIndexOrder =
    flip NonEmpty.sortWith (getRawVotes votes) $ \case
      WFALSPersistentVote seatIndex _ _ _ -> seatIndex
      WFALSNonPersistentVote seatIndex _ _ _ _ -> seatIndex

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-586)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
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
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)

    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig

    -- Verify VRF outputs for non-persistent voters (if any)
    case catMaybes (NonEmpty.toList optionalVRFKeysAndOutputs) of
      -- No non-persistent voters => no VRF outputs to verify
      [] -> do
        pure ()
      -- Some non-persistent voters => verify their aggregate VRF outputs
      vrfKeysAndOutputs -> do
        let (vrfVerificationKeys, vrfOutputs) =
              munzip
                . NonEmpty.fromList -- safe 'vrfKeysAndOutputs' /= []
                $ vrfKeysAndOutputs
        bimap InvalidCertSignature id $
          batchVerifyVRFOutputs
            vrfVerificationKeys
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
            vrfOutputs

    -- Return the list of voters attesting the election winner
    pure members
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L247-271)
```haskell
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
  allVotesMatchTarget target =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
