### Title
Epoch-Agnostic Peras Vote Validation Allows Unauthorized Certificate Forging and Chain-Selection Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`)

---

### Summary

The production Peras vote ingestion path validates incoming votes using only a flat stake-distribution lookup, with no check of epoch-specific committee membership, VRF eligibility proofs, or vote signatures. The function `getVotingCommitteeForElection` that is supposed to resolve the correct per-epoch committee for a given election is permanently unimplemented (`error "TODO"`). As a result, any pool present in the current `PerasVoteStakeDistr` can have votes accepted for any round — including rounds from past epochs — enabling unauthorized certificate forging and Peras weight-based chain-selection manipulation.

---

### Finding Description

**Root cause 1 — `getVotingCommitteeForElection` is permanently unimplemented:**

`AcrossEpochs.hs` is the module that is supposed to resolve which epoch's `VotingCommittee` applies to a given `ElectionId`, so that votes and certificates can be validated against the correct epoch's committee selection. Its sole query function is:

```haskell
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
``` [1](#0-0) 

A grep across the entire repository confirms this function is never called from any production file — it exists only in `AcrossEpochs.hs` itself. The `InterEpochVotingCommittee` structure that stores both the current and previous epoch's committee is therefore never consulted during vote validation.

**Root cause 2 — Production vote validation is a stake-lookup-only placeholder:**

Both production pool writers (`makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`) call `validatePerasVote mkPerasParams sd vote`, where `sd` is the current `PerasVoteStakeDistr`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [2](#0-1) [3](#0-2) 

The `validatePerasVote` implementation (the only deployed instance) does nothing beyond a `Map.lookup` of the voter ID in the current stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [4](#0-3) 

The following checks are entirely absent:
- Whether the vote's `PerasRoundNo` belongs to the current or a past epoch
- Whether the voter was actually selected for the committee in that round (persistent or non-persistent seat via VRF)
- Whether the vote carries a valid cryptographic signature
- Whether the VRF eligibility proof is valid (for non-persistent members)

The TODO comments in both pool writers explicitly acknowledge this gap:

```
-- TODO: in the future we won't need just the stake distribution for
-- validating votes, but also the whole committee selection context
-- (containing vote weights of committee members = voters)
``` [5](#0-4) 

**Root cause 3 — Accepted votes retain their stake weight across epoch transitions:**

Once a vote passes `validatePerasVote`, it is stored in `PerasVoteDB` as a `ValidatedPerasVote` with a fixed `vpvVoteStake` stamped at ingestion time. The `PerasVoteDB` garbage-collects by target slot, not by epoch:

```haskell
(\rvs -> getPerasRoundVoteStateMaxTargetedSlot rvs < NotOrigin slotNo)
``` [6](#0-5) 

A vote targeting a block in the volatile suffix will not be GC'd until that block becomes immutable, which can span an epoch boundary. During that window, the stored `vpvVoteStake` is never re-evaluated against the updated stake distribution, directly mirroring the `s_votesByPool` persistence bug in the external report.

---

### Impact Explanation

An unprivileged peer can send crafted `PerasVote` objects for any round number (including rounds from past epochs) using any `PerasVoterId` that appears in the current stake distribution. Each such vote passes `validatePerasVote`, is stored in `PerasVoteDB`, and contributes its full `vpvVoteStake` toward the quorum threshold for that round. Once the accumulated stake for a `(round, block)` target exceeds the quorum threshold, `updatePerasRoundVoteStates` automatically forges a `ValidatedPerasCert`: [7](#0-6) 

That certificate is then added to `PerasCertDB` and immediately reflected in the `PerasWeightSnapshot`, boosting the weight of the targeted block in chain selection: [8](#0-7) 

The Peras weight boost (`perasWeight = PerasWeight 15` by default) is additive and can cause the node to prefer a non-canonical or adversarially chosen chain over the honest longest chain, constituting a **chain-selection safety failure** and a **Peras voting/certificate verification bypass**.

---

### Likelihood Explanation

The object diffusion mini-protocol for Peras votes is wired into the production `ChainDB` path via `makePerasVotePoolWriterFromChainDB`. Any peer that can establish a connection to the node can submit `PerasVote` objects. No special privileges, keys, or stake are required beyond appearing in the current `PerasVoteStakeDistr` — which is public information derivable from the ledger state. The attack requires only crafting valid CBOR-serialized `PerasVote` structs with a known `PerasVoterId`.

---

### Recommendation

1. **Implement `getVotingCommitteeForElection`** in `AcrossEpochs.hs` to resolve the correct epoch's committee for a given `ElectionId`, and wire it into the vote validation path so that committee membership, VRF eligibility, and cryptographic signatures are verified before a vote is accepted.

2. **Replace the placeholder `validatePerasVote`** with a full implementation that checks: (a) the vote's round belongs to the current or immediately preceding epoch, (b) the voter holds a valid committee seat (persistent or non-persistent via VRF), and (c) the vote signature is valid.

3. **Re-validate stored vote weights on epoch transition** or, equivalently, garbage-collect votes whose originating epoch's committee selection is no longer valid, analogous to the per-epoch tracking recommended in the external report.

---

### Proof of Concept

1. Observe the current `PerasVoteStakeDistr` from the ledger state (public).
2. Pick any `PerasVoterId` present in the distribution with non-zero stake.
3. Craft a `PerasVote` with an arbitrary `pvVoteRound` (e.g., a round from a past epoch) and a target block point of your choice.
4. Send the vote via the object diffusion mini-protocol to the victim node.
5. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; since the voter ID is in `sd`, the vote is accepted and stored with the voter's current stake weight.
6. Repeat with enough distinct voter IDs until the accumulated `ptvtTotalStake` for the chosen `(round, block)` target exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin` (default: 0.76 of total stake).
7. `updateCandidateVoteState` forges a `ValidatedPerasCert` for the chosen block, which is added to `PerasCertDB` and boosts that block's weight by `PerasWeight 15` in chain selection — without any legitimate committee having voted. [9](#0-8) [1](#0-0)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L68-74)
```haskell
-- | Get the voting committee corresponding to an election, if any
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L108-110)
```haskell
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-111)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-211)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L311-313)
```haskell
        (roundsToDelete, pvsRoundVoteStates') =
          Map.partition
            (\rvs -> getPerasRoundVoteStateMaxTargetedSlot rvs < NotOrigin slotNo)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
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
