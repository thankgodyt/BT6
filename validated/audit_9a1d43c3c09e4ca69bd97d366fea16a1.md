### Title
`validatePerasVote` Default Instance Accepts Votes Without Signature Verification, Allowing Any Peer to Forge Votes for Arbitrary Pools — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasVote` implementation only checks that the claimed `pvVoteVoterId` is present in the stake distribution. It performs no cryptographic signature verification and the default `PerasVote blk` associated data type carries no signature field at all. An unprivileged peer can craft `PerasVote` messages claiming to be from any pool in the stake distribution, pass all validation, and artificially drive a node to reach Peras quorum for an attacker-chosen block.

---

### Finding Description

**Root cause — missing identity binding in `validatePerasVote`:**

The `BlockSupportsPeras` class exposes `validatePerasVote` as the sole gate for accepting inbound Peras votes. The default catch-all instance (explicitly labelled "degenerate instance for all blks to get things to compile") defines the associated `PerasVote blk` type without any signature or eligibility-proof field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- claimed identity, never authenticated
  }
``` [1](#0-0) 

The corresponding validation function accepts any vote whose `pvVoteVoterId` appears in the stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` resolves the stake purely from the claimed `pvVoteVoterId`: [3](#0-2) 

**Production entry path — `processVotes` / `makePerasVotePoolWriterFromChainDB`:**

The production vote-ingestion pipeline in `makePerasVotePoolWriterFromChainDB` wires `validatePerasVote` directly as the validation callback passed to `processVotes`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

`processVotes` accepts every vote that passes `validateVote` and stores it as a `ValidatedPerasVote` with the stake weight taken from the stake distribution: [5](#0-4) 

**Contrast with the correct implementation:**

The concrete `WFALS` committee scheme's `implVerifyVote` verifies both the BLS vote signature and the VRF eligibility proof before accepting a vote: [6](#0-5) 

The default instance performs neither check. No more-specific `BlockSupportsPeras` instance for `CardanoBlock` exists in the repository; the default instance is therefore the live production code path whenever Peras vote diffusion is active.

**Exploit flow:**

1. Attacker reads the current `PerasVoteStakeDistr` (public ledger data).
2. For each pool `p_i` in the distribution, attacker constructs `PerasVote { pvVoteRound = r, pvVoteBlock = B, pvVoteVoterId = p_i }` targeting an attacker-chosen block `B`.
3. Attacker sends the batch to the victim node via the object-diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote` for each vote; every vote passes because each `pvVoteVoterId` is in the stake distribution.
5. The node accumulates `ValidatedPerasVote` entries whose combined `vpvVoteStake` exceeds the quorum threshold.
6. `votesReachQuorum` returns `Just (ValidatedPerasVotesWithQuorum …)` and the node boosts block `B`. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can impersonate every pool in the stake distribution simultaneously, manufacture a Peras quorum for any block of its choice, and cause honest nodes to boost that block. This is a direct bypass of Peras voting authorization: the node accepts votes whose claimed voter identity is never bound to any cryptographic proof of key possession. The resulting artificial boost can steer chain selection toward an attacker-preferred chain, constituting a consensus safety failure. This matches the **Critical** impact category: "Bypass of… Peras voting or certificate checks… that enables unauthorized… vote… acceptance."

---

### Likelihood Explanation

The attack requires no privileged access, no stake, and no key material. The stake distribution is public. Any peer reachable by the object-diffusion protocol can execute the attack in a single message batch. The only precondition is that the Peras vote-diffusion path is active on the target node, which is the intended production configuration once Peras is enabled.

---

### Recommendation

Replace the stub `validatePerasVote` with an implementation that:
1. Requires the `PerasVote blk` associated type to carry a cryptographic signature (as `V1.PerasVote` already does via `pvSignature :: VoteSignature PerasBLSCrypto`).
2. Verifies the BLS vote signature against the public key of the pool identified by `pvVoteVoterId` in the stake distribution.
3. For non-persistent voters, verifies the VRF eligibility proof (`pvEligibilityProof`) against the epoch nonce and election identifier, mirroring `implVerifyVote` in `WFALS.hs`.

Until a concrete per-era instance is in place, the default instance should return `Left PerasValidationErr` unconditionally rather than silently accepting unauthenticated votes.

---

### Proof of Concept

```
-- Attacker node pseudocode (no keys required)
stakeDistr <- fetchStakeDistribution targetNode          -- public ledger data
let forgedVotes =
      [ PerasVote
          { pvVoteRound   = currentRound
          , pvVoteBlock   = attackerChosenBlock
          , pvVoteVoterId = poolId
          }
      | poolId <- Map.keys (unPerasVoteStakeDistr stakeDistr)
      ]
sendObjectDiffusionBatch targetNode forgedVotes
-- processVotes calls validatePerasVote for each vote;
-- every vote passes because pvVoteVoterId ∈ stakeDistr.
-- Combined vpvVoteStake exceeds quorum threshold.
-- Node boosts attackerChosenBlock.
```

The degenerate `validatePerasVote` at lines 363–371 of `SupportsPeras.hs` is the necessary vulnerable step: it returns `Right` for any vote whose claimed voter ID appears in the distribution, with no signature check, making the forged votes indistinguishable from legitimate ones. [8](#0-7)

### Citations

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
