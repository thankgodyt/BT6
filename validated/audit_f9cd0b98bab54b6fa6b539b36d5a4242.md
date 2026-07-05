### Title
Missing Cryptographic Signature Verification in `validatePerasVote` Allows Unprivileged Vote Forgery and Artificial Quorum - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default implementation of `validatePerasVote` in the `BlockSupportsPeras` typeclass checks only whether a voter's ID appears in the stake distribution, but performs **no cryptographic signature verification**. An unprivileged peer can craft votes claiming to be any legitimate voter in the public stake distribution, submit them through the object-diffusion mini-protocol, and have them accepted and counted toward quorum. This is the direct analog of the external report's pattern: a check is performed against an identifier (voter ID in the stake distribution) rather than against the underlying authorization (a valid cryptographic signature proving key ownership), allowing the check to be bypassed by any party who can observe the public identifier.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` with a default implementation that is the sole implementation in the codebase:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

The check is purely a map lookup: if `pvVoteVoterId` appears as a key in `PerasVoteStakeDistr`, the vote is accepted and stamped with that voter's stake weight. No signature over the vote message is verified, no committee eligibility proof is checked, and no VRF output is evaluated. [2](#0-1) 

This validation is invoked directly in the inbound vote processing path. `processVotes` — called from both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` — runs `validateVote` inside an STM transaction for every vote received from a peer, then adds all validated votes to the `PerasVoteDB`:

```haskell
validationResults <- atomically $ do
  alreadyInDb <- alreadyInDbSTM
  let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
  mapM validateVote votesNotAlreadyInDb
``` [3](#0-2) 

The production writer wires in the stub validator directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

Once a vote passes this check, `implAddVote` inserts it into `pvdsVoteIds` (keyed by `PerasVoteId = (roundNo, voterId)`) and accumulates its stake in `pvdsRoundVoteStates`. The deduplication guard inside `implAddVote` only prevents the same `(roundNo, voterId)` pair from being inserted twice — it does not re-verify the vote's authenticity:

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
``` [5](#0-4) 

The stake accumulation and quorum check then proceed normally: [6](#0-5) 

The parallel to the external report is exact: the external contract checked `claimed[epoch][tokenId]` (an identifier) rather than verifying ownership of the underlying locked tokens. Here, the code checks `voterId ∈ stakeDistr` (an identifier) rather than verifying ownership of the underlying signing key. In both cases, any party who can observe the public identifier can bypass the authorization check.

---

### Impact Explanation

An unprivileged peer who observes the public `PerasVoteStakeDistr` can:

1. Enumerate all `PerasVoterId` keys in the distribution.
2. Craft a `PerasVote` for each voter for a target round and block, setting `pvVoteVoterId` to each key in turn.
3. Submit these crafted votes through the object-diffusion mini-protocol.
4. Each vote passes `validatePerasVote` (the voter ID is in the distribution) and is inserted into the `PerasVoteDB` with the corresponding stake weight.
5. Once the accumulated stake exceeds the quorum threshold, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert` for the attacker's chosen block. [7](#0-6) 

The forged certificate is then processed by ChainDB chain selection, causing honest nodes to boost an attacker-chosen block by `perasWeight` additional chain weight. This constitutes a **bypass of Peras voting checks enabling unauthorized certificate acceptance**, which falls squarely within the Critical allowed impact scope.

---

### Likelihood Explanation

The stake distribution (`PerasVoteStakeDistr`) is derived from the public ledger state and is available to any node. No private key material, stake majority, or privileged access is required. The attack path is entirely through the standard object-diffusion mini-protocol, which is open to any peer. The only constraint is that the attacker must send enough distinct voter IDs to accumulate stake above the quorum threshold, which is straightforward given the public distribution.

---

### Recommendation

The `validatePerasVote` implementation must verify the cryptographic signature carried in the vote before accepting it. For the `WFALS` and `EveryoneVotes` committee schemes already present in the codebase, this means verifying the `VoteSignature` (and, for non-persistent members, the VRF eligibility proof) against the voter's public key retrieved from the committee state — mirroring the pattern already implemented in `implVerifyVote` for those schemes. [8](#0-7) 

The tracked issue `https://github.com/tweag/cardano-peras/issues/120` (referenced in the TODO comments) should be treated as a security-critical fix, not a deferred enhancement.

---

### Proof of Concept

```
Attacker node A connects to honest node H via the object-diffusion mini-protocol.

1. A reads the public PerasVoteStakeDistr from the ledger state:
     stakeDistr = { voterId_1 → stake_1, voterId_2 → stake_2, ..., voterId_n → stake_n }

2. A selects a target block B and round R.

3. For each voterId_i with stake_i such that Σ stake_i > quorumThreshold + safetyMargin:
     A crafts PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = voterId_i }
     (no private key required — the signature field is absent in the stub PerasVote type)

4. A sends the batch to H via the object-diffusion inbound handler.

5. processVotes on H:
     - atomically checks alreadyInDb (empty for round R) → all votes pass the ID filter
     - validatePerasVote checks voterId_i ∈ stakeDistr → Right (ValidatedPerasVote { vpvVoteStake = stake_i })
     - all votes are added to the PerasVoteDB

6. implAddVote accumulates stake; once Σ stake_i > threshold,
   updatePerasRoundVoteStates forges ValidatedPerasCert { pcCertBoostedBlock = B, pcCertRound = R }.

7. ChainDB processes the certificate, boosting block B by perasWeight in chain selection.
   Honest node H now prefers a chain ending at B, chosen entirely by the attacker.
``` [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L195-203)
```haskell
-- | Lookup the stake of a vote cast by a member of a given stake distribution.
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-142)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-189)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-211)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L361-392)
```haskell
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
