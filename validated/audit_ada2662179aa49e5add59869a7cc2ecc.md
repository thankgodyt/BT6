### Title
Peras Quorum Check Compares Unnormalized Absolute Stake Against Relative Threshold, Enabling Single-Vote Certificate Forgery — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` directly compares the accumulated `PerasVoteStake` (populated from the ledger's absolute stake distribution) against `perasQuorumStakeThreshold` (a relative value, e.g., `3/4`). The code itself documents this unit mismatch as an unresolved TODO. Because any absolute lovelace amount (e.g., `1_000_000`) trivially exceeds the relative threshold (`0.77`), a single vote from any peer with any positive ledger stake immediately triggers quorum and forges a Peras certificate for an arbitrary block, bypassing the intended quorum requirement entirely.

---

### Finding Description

**Root cause — `stakeAboveThreshold`:** [1](#0-0) 

The function compares `unPerasVoteStake voteStake` (a raw `Rational`) directly against `unPerasQuorumStakeThreshold + unPerasQuorumStakeThresholdSafetyMargin`. The code's own TODO comment (lines 153–161) states:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

The quorum threshold is a relative value (`3/4 = 0.75` plus a safety margin of `2/100`): [2](#0-1) 

**How `PerasVoteStake` is populated:**

During `validatePerasVote`, the voter's stake is looked up directly from `PerasVoteStakeDistr` and stored verbatim in `vpvVoteStake`: [3](#0-2) 

The `PerasVoteStakeDistr` is sourced from the ledger's stake distribution (absolute lovelace values), provided via `getStakeDistrSTM`: [4](#0-3) 

**Quorum check path:**

`votesReachQuorum` sums `vpvVoteStake` values and calls `stakeAboveThreshold`: [5](#0-4) 

`updateCandidateVoteState` calls `votesReachQuorum` and, on `Just`, immediately forges a certificate: [6](#0-5) 

**Attack path (end-to-end):**

1. Attacker (any peer with any positive ledger stake) sends a single `PerasVote` via the object diffusion mini-protocol for a target block of their choice.
2. `processVotes` validates the vote; `validatePerasVote` assigns the voter's absolute ledger stake (e.g., `1_000_000` lovelace) to `vpvVoteStake`. [7](#0-6) 

3. `implAddVote` calls `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold`. [8](#0-7) 

4. `stakeAboveThreshold` evaluates `1_000_000 >= 0.75 + 0.02` → `True`. Quorum is declared reached.
5. A `ValidatedPerasCert` is forged for the attacker's chosen block, boosting it by `perasWeight = 15` blocks in chain selection.

**Analog to the external report:**

The external report's bug was using `address(this).balance` (an externally-manipulable value) instead of `_auction.amount` (the internally-tracked state) in a guard condition. Here, the guard uses the raw absolute ledger stake (a value in a different unit domain than the threshold) instead of the normalized relative stake. In both cases, the guard condition is trivially satisfied by a value that was never intended to be compared against the threshold directly.

---

### Impact Explanation

**Critical.** Any unprivileged peer who is a registered voter with any positive ledger stake can forge a Peras certificate for an arbitrary block with a single vote. The forged certificate boosts that block's chain-selection weight by `perasWeight` (15 blocks), potentially causing honest nodes to prefer an adversarial chain over the canonical honest chain. This is a complete bypass of the Peras quorum/certificate verification check.

---

### Likelihood Explanation

Any peer with any positive stake in the ledger's stake distribution can trigger this. The entry point is the publicly reachable object diffusion mini-protocol for Peras votes. No privileged access, key compromise, or stake majority is required — a single vote from a voter with even minimal stake suffices.

---

### Recommendation

Normalize `PerasVoteStake` to a relative value (fraction of total committee stake) before calling `stakeAboveThreshold`, or change `stakeAboveThreshold` to accept the total stake distribution and perform normalization internally. The fix must ensure the accumulated vote stake and the quorum threshold are expressed in the same units before comparison. The existing TODO comment at lines 153–161 of `SupportsPeras.hs` already identifies the correct fix direction: [9](#0-8) 

---

### Proof of Concept

```
Preconditions:
  - Peras is active on the node.
  - PerasVoteStakeDistr is populated with absolute ledger stake values
    (e.g., voter V has 1_000_000 lovelace in the distribution).
  - perasQuorumStakeThreshold = 3/4, safetyMargin = 2/100.

Steps:
  1. Attacker (voter V) sends one PerasVote for block B via the
     object diffusion mini-protocol.
  2. validatePerasVote assigns vpvVoteStake = PerasVoteStake (1_000_000 % 1).
  3. votesReachQuorum computes totalVoteStake = 1_000_000.
  4. stakeAboveThreshold: 1_000_000 >= (3/4 + 2/100) = 0.77 → True.
  5. forgePerasCert is called; a ValidatedPerasCert for block B is stored.
  6. Chain selection now treats block B as boosted by 15 blocks.

Expected (correct) behavior:
  - totalVoteStake should be normalized (e.g., 1_000_000 / total_committee_stake)
    before comparison, yielding a value in [0,1].
  - A single voter cannot reach the 77% quorum threshold alone.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L109-113)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
```
