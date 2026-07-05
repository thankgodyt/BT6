### Title
`validatePerasVote` and `validatePerasCert` Perform No Cryptographic Signature Verification, Allowing Any Peer to Forge Votes and Certificates — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` and `validatePerasCert` implementations perform no cryptographic signature verification. Any unprivileged peer can send crafted `PerasVote` or `PerasCert` messages claiming to be from any registered stake pool, and the node will accept and count them toward quorum. This is the direct analog of the Astaria replay bug: in Astaria, the signed data omitted the vault address so the same signature was valid in a different context; here, no signature is checked at all, so any voter identity can be used in any context.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` and `validatePerasCert` as the entry points for cryptographic validation of inbound Peras votes and certificates. The production instance (the "degenerate instance for all blks") implements both as stubs:

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

`validatePerasVote` only checks that the claimed `pvVoteVoterId` exists in the stake distribution. It does **not** verify any BLS signature over `(roundNo, boostedBlock)`. The `validatePerasCert` implementation is even weaker — it accepts every certificate unconditionally:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

These stubs are called directly from the production vote-ingestion path. `processVotes` in the object-diffusion layer calls `validateVote` (which resolves to `validatePerasVote`) on every inbound vote that is not already in the database:

```haskell
let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
mapM validateVote votesNotAlreadyInDb
``` [3](#0-2) 

The deduplication key is `PerasVoteId = (roundNo, voterId)` — it does **not** include the boosted block. This means:

1. An attacker can send a crafted vote for voter X in round R for attacker-chosen block B. Since no signature is checked, it passes validation and is stored.
2. The legitimate vote from voter X for the canonical block A arrives later. It is silently dropped as a duplicate (same `(R, X)` ID).
3. The attacker can repeat this for enough voters to exceed the quorum threshold, triggering certificate forging for block B.

The `PerasVoteDB` implementation mirrors this: `implAddVote` calls `updatePerasRoundVoteStates` which calls `votesReachQuorum` and `forgePerasCert` — all of which operate on already-"validated" votes. [4](#0-3) 

The `forgeCert` path in `updateCandidateVoteState` will produce a real certificate once quorum is reached: [5](#0-4) 

---

### Impact Explanation

**Critical — Bypass of Peras voting and certificate checks enabling unauthorized certificate acceptance.**

An attacker who can connect as a peer can:
- Forge votes for any registered stake pool without possessing any private key.
- Accumulate enough forged votes to trigger a false quorum for an attacker-chosen block.
- Cause the node to forge and store a Peras certificate boosting that block.
- The Peras boost directly affects chain selection via `PerasSelectView`, causing the node to prefer the attacker's block over the canonical chain. [6](#0-5) 

This is a consensus safety failure: an honest node accepts an invalid ledger state (a certificate for a block that was not legitimately voted for), driven entirely by crafted network messages from an unprivileged peer.

---

### Likelihood Explanation

**High.** The attack requires only:
1. A TCP connection to the target node (standard peer connectivity).
2. Knowledge of the current stake distribution (publicly available on-chain).
3. Sending well-formed `PerasVote` CBOR messages with valid voter IDs from the distribution.

No key material, stake, or privileged access is needed. The `processVotes` entry point is reachable from any connected peer via the vote-diffusion mini-protocol. [7](#0-6) 

---

### Recommendation

Replace the stub implementations with real cryptographic validation before the Peras vote-diffusion mini-protocol is enabled on any network:

1. **`validatePerasVote`**: Verify the BLS vote signature over `(roundNo, boostedBlock)` using the voter's public key from the stake distribution / committee context. The `verifyVote` method of `CryptoSupportsVotingCommittee` already provides this interface. [8](#0-7) 

2. **`validatePerasCert`**: Verify the aggregate BLS signature over `(electionId, candidate)` against the aggregate public key of the declared voters, and verify each non-persistent voter's VRF output. The `verifyCert` method of `CryptoSupportsVotingCommittee` already provides this interface. [9](#0-8) 

3. Ensure the deduplication key (`PerasVoteId`) is checked **after** signature validation, not before, so that a forged vote for voter X cannot suppress the legitimate vote from voter X for a different block.

---

### Proof of Concept

An attacker node connects to a target node and sends the following sequence of CBOR-encoded `PerasVote` messages via the vote-diffusion mini-protocol, one per registered stake pool in the current epoch's stake distribution, all claiming to vote for attacker-chosen block `B` in round `R`:

```
PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = pool_1 }
PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = pool_2 }
...
PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = pool_N }
```

Each vote passes `validatePerasVote` because each `pool_i` exists in the stake distribution. Once the accumulated stake exceeds `perasQuorumThreshold`, `votesReachQuorum` returns `Just`, `forgePerasCert` is called, and a certificate boosting block `B` is stored in the `PerasVoteDB` and forwarded to `ChainDB`. The target node's chain selection now treats block `B` as having a Peras boost, potentially causing it to prefer a non-canonical chain. [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L100-117)
```haskell
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L179-182)
```haskell
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-217)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L1-10)
```haskell
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Ouroboros.Consensus.Peras.SelectView
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L95-101)
```haskell
  -- | Verify a vote cast by a committee member in a given election
  verifyVote ::
    VotingCommittee crypto committee ->
    Vote crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (EligibilityWitness crypto committee)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-586)
```haskell
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
