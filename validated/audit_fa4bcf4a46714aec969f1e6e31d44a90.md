### Title
Peras Vote Signature Verification Bypass Allows Unprivileged Peer to Forge Quorum Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation is a stub that only checks whether a voter ID exists in the stake distribution. It performs no cryptographic signature verification on the vote body. An unprivileged peer can send crafted `PerasVote` messages claiming to be any registered stake pool, for any block target, and the node will accept them as valid, count their stake toward quorum, and potentially forge a certificate for an attacker-chosen block.

---

### Finding Description

The `BlockSupportsPeras` instance for `StandardHash blk` in `SupportsPeras.hs` implements `validatePerasVote` as a stub:

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

The only check performed is `lookupPerasVoteStake`, which looks up the voter ID in the stake distribution map. No BLS signature over `(roundNo, boostedBlock)` is verified. The `pvSignature` field of the concrete `PerasVote` type (defined in `V1.hs`) is completely ignored. [2](#0-1) 

This stub is the function called by the production inbound vote handler `processVotes` in `PerasVote.hs`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) 

`processVotes` is the live network handler that processes all inbound Peras votes from peers. It filters already-seen vote IDs, then calls `validateVote` on the remainder, and adds all that pass to the `PerasVoteDB`: [4](#0-3) 

Once a vote is accepted into the `PerasVoteDB`, `implAddVote` calls `updatePerasRoundVoteStates` to accumulate stake. When the stake total for a target block crosses the quorum threshold, a `ValidatedPerasCert` is forged automatically: [5](#0-4) 

The deduplication guard in `addOrIgnoreVote` only checks `(voterId, roundNo)` — the `PerasVoteId`. An attacker who uses a different voter ID per forged vote (all drawn from the public stake distribution) bypasses this guard entirely. [6](#0-5) 

The `PerasVoteId` is defined as `(pviRoundNo, pviVoterId)` — it does not include the block target or the signature: [7](#0-6) 

**Exploit path:**

1. Attacker connects as a peer to a target node.
2. Attacker reads the public stake distribution (available via the ledger state query protocol) to enumerate registered pool IDs and their stake weights.
3. Attacker crafts `PerasVote` messages for each pool ID, all targeting the same attacker-chosen block in a given round, with arbitrary or zeroed signatures.
4. `processVotes` filters out none of them (all have distinct `PerasVoteId`s and all pass `validatePerasVote` because their voter IDs are in the stake distribution).
5. Each vote is added to the `PerasVoteDB` and its stake is accumulated.
6. Once the accumulated stake crosses the quorum threshold, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert` for the attacker-chosen block.
7. The certificate is passed to `addPerasCertAsync` → ChainDB, where it boosts the chain weight of the attacker-chosen block in chain selection. [8](#0-7) 

---

### Impact Explanation

A Peras certificate artificially forged for an attacker-chosen block boosts that block's chain weight by `perasWeight` in chain selection. This can cause an honest node to prefer a non-canonical or adversarially-selected chain over the honest chain, constituting a **chain selection manipulation** and **unauthorized certificate acceptance**. This maps to:

> **High**: Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

> **Critical**: Bypass of certificate/signature validation that enables unauthorized certificate acceptance.

---

### Likelihood Explanation

The stake distribution is publicly readable via the node-to-client state query protocol. Any peer connected to the node can send crafted votes. No key material, admin access, or stake majority is required. The attacker only needs to know the pool IDs in the current stake distribution, which are public. The attack is executable in a single round-trip batch of votes.

---

### Recommendation

Implement actual BLS signature verification inside `validatePerasVote`. The `pvSignature` field of the concrete `PerasVote` (from `V1.hs`) must be verified against the voter's public key and the signed message `(roundNo, boostedBlock)` using `verifyVoteSignature` from the `CryptoSupportsVoteSigning` interface before a vote is accepted as `ValidatedPerasVote`. The existing `verifyVoteSignature` / `verifyWithRole` infrastructure in `Peras/Crypto/BLS.hs` is already in place and only needs to be wired into `validatePerasVote`. [9](#0-8) 

---

### Proof of Concept

```
1. Query the node's stake distribution via LocalStateQuery to obtain all
   registered pool IDs and their stake fractions.

2. For a target round R and attacker-chosen block B, construct N crafted votes:
     vote_i = PerasVote
       { pvVoteRound    = R
       , pvVoteBlock    = B          -- attacker-chosen block
       , pvVoteVoterId  = pool_i     -- legitimate pool ID from stake distribution
       , pvSignature    = zeroed_sig -- ignored by validatePerasVote stub
       }
   where pool_1 ... pool_N are distinct pool IDs whose combined stake > quorum threshold.

3. Send all vote_i to the target node via the Peras vote diffusion mini-protocol.

4. processVotes accepts all votes (each has a distinct PerasVoteId and each
   pool_i is in the stake distribution).

5. updatePerasRoundVoteStates accumulates stake; once threshold is crossed,
   a ValidatedPerasCert for block B is forged and submitted to ChainDB.

6. ChainDB applies the certificate boost to block B's chain weight, potentially
   causing the node to switch to a chain containing B.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-200)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L199-230)
```haskell
updatePerasRoundVoteState ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  PerasRoundVoteState blk ->
  Either (UpdateRoundVoteStateError blk) (PerasRoundVoteState blk)
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
    case roundState of
      -- Quorum not yet reached
      state@PerasRoundVoteState
        { prvsState =
          Left
            NoQuorum
              { candidateStates
              }
        } -> do
          let oldCandidateState =
                Map.findWithDefault
                  (freshCandidateVoteState (getPerasVoteTarget vote))
                  (getPerasVoteBlock vote)
                  candidateStates
          candidateOrWinnerState <-
            updateCandidateVoteState cfg vote oldCandidateState
              `onErr` \err ->
                RoundVoteStateForgingCertError err
          case candidateOrWinnerState of
            RemainedCandidate newCandidateState -> do
              -- Quorum still not reached for this round
              let prvsCandidateStates' =
                    Map.insert
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L162-170)
```haskell
  verifyVoteSignature
    pk
    roundNo
    boostedBlock
    (PerasBLSCryptoVoteSignature sig) =
      BLS.verifyWithRole @SIGN
        pk
        (hashVoteSignature roundNo boostedBlock)
        sig
```
