### Title
Peras Vote Signature Verification Bypass Allows Forged Certificates via Unauthenticated Votes - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation in the `BlockSupportsPeras` instance performs no cryptographic signature verification on incoming votes. The `PerasVote blk` data type in this instance carries no signature field at all. Any unprivileged peer can send votes claiming to be any legitimate committee member (using their publicly known `PerasVoterId`), bypass validation, accumulate stake in the quorum tally, and cause the node to forge a Peras certificate for an attacker-chosen block — directly analogous to the Babylon covenant committee signature bypass.

---

### Finding Description

The `BlockSupportsPeras` production instance defines `validatePerasVote` as a stub that only checks whether the voter ID exists in the stake distribution:

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

The `PerasVote blk` data type in this same instance carries **no signature field**:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [2](#0-1) 

This stub is the instance used in production (the `instance StandardHash blk => BlockSupportsPeras blk` catch-all). The concrete `V1.PerasVote` type that does carry a `pvSignature :: VoteSignature PerasBLSCrypto` field is not wired into this instance. [3](#0-2) 

The inbound vote processing path in `processVotes` calls this stub validator for every vote received from a peer:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

A vote that passes this check is timestamped and forwarded directly to `implAddVote`, which itself carries a TODO acknowledging missing validation:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote :: ...
``` [5](#0-4) 

Once inside `implAddVote`, the vote is fed into `updatePerasRoundVoteStates`, which accumulates stake and triggers `votesReachQuorum` → `forgePerasCert` when the quorum threshold is exceeded: [6](#0-5) [7](#0-6) 

The `validatePerasCert` implementation is equally hollow — it always returns `Right` without any cryptographic check:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [8](#0-7) 

---

### Impact Explanation

A malicious peer can forge Peras votes for any block target on behalf of any legitimate committee member, using only their publicly visible `PerasVoterId` (a stake pool key hash). No private key material is needed. By sending enough forged votes to exceed the quorum threshold, the attacker causes the node to forge a `ValidatedPerasCert` for an attacker-chosen block. This certificate is then used in Peras chain selection (boosting), causing the honest node to prefer a non-canonical chain. This is a **Critical** bypass of vote/certificate signature validation enabling unauthorized certificate acceptance and chain selection manipulation.

---

### Likelihood Explanation

The `PerasVoterId` values (stake pool key hashes) are publicly visible on-chain. Any peer connected via the object diffusion mini-protocol can send crafted `PerasVote` messages. No stake, no keys, and no special privilege are required — only knowledge of the stake distribution, which is public. The attack requires sending O(quorum) forged votes, which is trivially cheap since no cryptographic work is involved.

---

### Recommendation

1. The `PerasVote blk` data type in the production `BlockSupportsPeras` instance must include a cryptographic signature field (as already done in `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`).
2. `validatePerasVote` must verify the BLS vote signature against the voter's public key from the committee/stake distribution before accepting the vote, analogous to `implVerifyVote` in `WFALS.hs` and `EveryoneVotes.hs`.
3. `validatePerasCert` must perform full aggregate signature and VRF verification before accepting a certificate, analogous to `implVerifyCert` in `WFALS.hs`.
4. The tracked issue `https://github.com/tweag/cardano-peras/issues/120` should be treated as a security-critical blocker before any production deployment.

---

### Proof of Concept

```
Attacker (unprivileged peer):
  1. Observe the current PerasVoteStakeDistr (public, from ledger state).
     Extract N voter IDs (PerasVoterId) whose combined stake exceeds the quorum threshold.
  2. For each voter ID v_i, construct:
       PerasVote { pvVoteRound = R, pvVoteBlock = attacker_block, pvVoteVoterId = v_i }
     No signature is needed — the PerasVote type has no signature field.
  3. Send these votes to the target node via the object diffusion mini-protocol.
  4. processVotes calls validatePerasVote for each vote.
     validatePerasVote only calls lookupPerasVoteStake — succeeds for all v_i.
  5. Each vote is added to PerasVoteDB via implAddVote.
  6. updatePerasRoundVoteStates accumulates stake; once quorum is exceeded,
     votesReachQuorum returns Just, and forgePerasCert creates a ValidatedPerasCert
     for attacker_block.
  7. The certificate boosts attacker_block in chain selection, causing the node
     to prefer a non-canonical chain without any legitimate committee participation.
``` [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-236)
```haskell
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
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr
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
