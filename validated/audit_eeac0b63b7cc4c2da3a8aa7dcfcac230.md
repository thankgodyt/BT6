### Title
Missing Peras Vote Signature Verification Allows Forged Votes to Accumulate and Trigger Unauthorized Certificate Forgery - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation for the universal `BlockSupportsPeras` instance performs no cryptographic verification of the vote. It only checks whether the claimed voter ID exists in the stake distribution. Because the `PerasVote` data type carries no signature field, any unprivileged peer can craft votes claiming to be from any staked pool. These forged votes pass validation, accumulate in the `PerasVoteDB`, and—once their combined stake exceeds the quorum threshold—cause the node to locally forge a `ValidatedPerasCert` boosting an attacker-chosen block. The same stub also unconditionally accepts any inbound `PerasCert` via `validatePerasCert`.

---

### Finding Description

The `BlockSupportsPeras` instance for all `StandardHash blk` (the universal production instance) defines `PerasVote` without a signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [1](#0-0) 

The corresponding `validatePerasVote` implementation only performs a stake-distribution lookup:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` simply does `Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)`: [3](#0-2) 

There is no check that the voter actually signed the vote, that the vote is for a valid round, or that the voter was selected by the committee mechanism. The `validatePerasCert` stub is equally permissive—it unconditionally returns `Right`: [4](#0-3) 

The inbound vote processing path in `processVotes` calls `validateVote` (bound to `validatePerasVote`) inside a single `atomically` block, then calls `addVote` outside it for each validated vote: [5](#0-4) 

Both production pool writers (`makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`) wire `validatePerasVote` directly as the validator: [6](#0-5) [7](#0-6) 

Once a forged vote passes validation, `implAddVote` inserts it into `pvdsVoteIds` and feeds it to `updatePerasRoundVoteStates`, which accumulates stake toward quorum: [8](#0-7) 

When accumulated stake crosses the threshold, `updateCandidateVoteState` calls `forgePerasCert` and the resulting `ValidatedPerasCert` is stored and used for chain selection: [9](#0-8) 

The analog to the external report is direct: just as removed voters' votes were not cleared and could still influence the outcome, here votes from voters who never actually cast them (forged votes) are not rejected and accumulate toward quorum, influencing chain selection.

---

### Impact Explanation

An unprivileged peer can cause a victim node to forge a `ValidatedPerasCert` boosting an arbitrary block. Because Peras certificates add `perasWeight` to a block's chain-selection score, this can make the node prefer a non-canonical or adversarially chosen chain over the honest chain. This is a **bypass of Peras vote/certificate verification** enabling unauthorized certificate acceptance and a chain-selection error.

---

### Likelihood Explanation

The vote diffusion miniprotocol is a public-facing network interface. Any peer that can connect to the node can send `PerasVote` messages. The attacker only needs to know the `PerasVoterId` (a `KeyHash` that is public on-chain) of staked pools. No key material is required. The attack requires sending enough forged votes to exceed the quorum threshold, which is feasible if the attacker knows the stake distribution (also public). Likelihood is **high** once Peras is activated.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote` and verify it in `validatePerasVote` against the voter's registered VRF/KES/vote key before accepting the vote.
2. Implement `validatePerasCert` to verify the aggregate signature and committee eligibility proofs embedded in the certificate, rather than unconditionally returning `Right`.
3. Resolve the tracked issues (`#120`, `#73`) before activating Peras on any network where the vote diffusion protocol is exposed to untrusted peers.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Observe the public stake distribution to enumerate `PerasVoterId` values with large stake.
2. Craft `PerasVote` messages with `pvVoteVoterId` set to those IDs, `pvVoteRound` set to the current round, and `pvVoteBlock` set to an attacker-chosen block point.
3. Send the crafted votes to the victim node via the vote diffusion miniprotocol.
4. `processVotes` → `validatePerasVote` passes each vote (stake lookup succeeds).
5. `implAddVote` → `updatePerasRoundVoteStates` accumulates the fake stake.
6. Once accumulated stake exceeds `perasQuorumThreshold`, `forgePerasCert` is called and a `ValidatedPerasCert` for the attacker's block is stored.
7. Chain selection now boosts the attacker's block by `perasWeight`, potentially causing the node to switch to a non-canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-113)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
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
