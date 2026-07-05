### Title
Peras Vote Validation Bypass: Missing Cryptographic Signature Check Allows Forged Votes to Reach Quorum and Generate Unauthorized Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `validatePerasVote` implementation in the universal `BlockSupportsPeras` instance only checks whether a voter ID exists in the stake distribution. It performs no cryptographic signature verification. Because the `PerasVote` data type carries no signature field at all, any unprivileged peer can send crafted votes claiming to be from any known committee member, for any block, without possessing that member's private key. These votes pass validation, are accumulated into the `PerasVoteDB`, and can push the stake tally past the quorum threshold, causing the node to forge and accept a fraudulent Peras certificate that boosts a non-canonical chain.

### Finding Description

**Root cause — no signature in the vote type and no cryptographic check in validation.**

The `PerasVote` data type contains only a round number, a target block point, and a voter ID: [1](#0-0) 

There is no signature field. The universal `BlockSupportsPeras` instance's `validatePerasVote` only looks up the voter ID in the stake distribution and, if found, wraps the vote as `ValidatedPerasVote` with the associated stake: [2](#0-1) 

The TODO comment explicitly acknowledges this is incomplete:

> `-- TODO: perform actual validation against all possible 'PerasValidationErr' variants`

**Entry path — peer-submitted votes via the object diffusion mini-protocol.**

Inbound votes from peers are processed by `processVotes` in `makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB`. The validation callback passed to `processVotes` is exactly the stub above: [3](#0-2) 

`processVotes` validates each vote in the batch and, if all pass, adds them to the database: [4](#0-3) 

**Deduplication does not prevent the attack.**

The `PerasVoteId` is `(roundNo, voterId)`. The DB deduplication check in `implAddVote` only prevents the same `(round, voter)` pair from being inserted twice: [5](#0-4) 

An attacker who knows the public voter IDs (which are derived from the public stake distribution) can send one forged vote per committee member per round, each for the same attacker-chosen block. Because voter IDs are public, no secret material is required.

**Quorum and certificate forging.**

Once accumulated stake exceeds the threshold, `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a `ValidatedPerasCert` with `vpcCertBoost = perasWeight params`: [6](#0-5) 

`validatePerasCert` — the certificate validation counterpart — is also a stub that unconditionally returns `Right`: [7](#0-6) 

The fraudulent certificate is then stored and used in chain selection via the Peras weight boost, causing the node to prefer the attacker-chosen block over the honest canonical chain. [8](#0-7) 

### Impact Explanation

**Severity: Critical — Bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer can forge votes on behalf of every committee member for a round (voter IDs are public), accumulate fake stake past the quorum threshold, and cause the local node to generate and accept a fraudulent Peras certificate for an attacker-chosen block. The certificate's `vpcCertBoost` weight is then applied during chain selection, making the node prefer a non-canonical chain. This directly violates the Peras safety guarantee that only honestly-voted blocks receive a boost.

### Likelihood Explanation

**High.** The attacker needs only:
1. A network connection to the target node (standard peer connection).
2. Knowledge of the current committee's voter IDs — these are derived from the public stake distribution, which is available on-chain.
3. No private keys, no stake, no privileged access.

The attack is executable in a single round by sending one crafted vote per committee member.

### Recommendation

1. **Add a cryptographic signature field to `PerasVote`** so that each vote carries a proof that the claimed voter actually cast it (e.g., a KES or BLS signature over `(roundNo, targetBlock, voterId)`).
2. **Implement `validatePerasVote` to verify that signature** against the voter's registered verification key before accepting the vote.
3. **Implement `validatePerasCert` to verify the certificate's aggregate proof** rather than unconditionally returning `Right`.
4. Track the referenced GitHub issue (`tweag/cardano-peras#120`) as a security-critical blocker before any production deployment of Peras.

### Proof of Concept

```
Attacker (no keys, no stake):
  1. Connect to target node as a normal peer.
  2. Read the current PerasVoteStakeDistr from the node's public state query API
     to enumerate all committee member voter IDs for round R.
  3. For each voterId_i in the committee, construct:
       PerasVote { pvVoteRound = R
                 , pvVoteBlock = <attacker-chosen block point>
                 , pvVoteVoterId = voterId_i }
  4. Send the batch via the object diffusion mini-protocol.
  5. processVotes calls validatePerasVote for each vote.
     validatePerasVote looks up voterId_i in the stake distribution → found → returns Right.
  6. Each vote is added to PerasVoteDB via implAddVote.
  7. updatePerasRoundVoteStates accumulates stake; once total > quorum threshold,
     forgePerasCert is called → ValidatedPerasCert with full perasWeight boost is stored.
  8. Chain selection now applies the boost to the attacker-chosen block,
     preferring it over the honest canonical chain.
```

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-200)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
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
