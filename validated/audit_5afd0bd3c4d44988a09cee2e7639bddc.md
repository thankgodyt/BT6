### Title
Unscaled `PerasVoteStake` Compared Against Relative Quorum Threshold in `stakeAboveThreshold` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value — which accumulates raw, potentially absolute stake values from `PerasVoteStakeDistr` — against a relative (normalized) quorum threshold (e.g., `3/4`). The code itself documents this unit mismatch as an unresolved TODO. Because the comparison is between incompatible units, the quorum check that gates Peras certificate forging is incorrect, enabling either unauthorized certificate forging from a single peer vote or permanent prevention of any certificate being forged.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the critical quorum check for the Peras protocol:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake    = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (...)
``` [1](#0-0) 

The `perasQuorumStakeThreshold` is a **relative** value (e.g., `3/4` of total committee stake):

```haskell
perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
``` [2](#0-1) 

The `PerasVoteStake` values are sourced from `PerasVoteStakeDistr` via `lookupPerasVoteStake` inside `validatePerasVote`, and then summed directly without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [3](#0-2) 

The code itself acknowledges the unit mismatch in a TODO comment directly above `stakeAboveThreshold`:

> *"this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."* [4](#0-3) 

The `PerasVoteStake` type's own comment also acknowledges the unresolved question:

> *"At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."* [5](#0-4) 

The accumulated `totalVoteStake` passed to `stakeAboveThreshold` inside `votesReachQuorum` is a raw sum of per-voter stakes from the distribution, not normalized to `[0,1]`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [6](#0-5) 

The same unscaled path is used in `updateCandidateVoteState` (the live aggregation path):

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [7](#0-6) 

And in `updateLoserVoteState`:

```haskell
let aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
``` [8](#0-7) 

---

### Impact Explanation

`PerasVoteStake` values sourced from the ledger's stake distribution are absolute lovelace-denominated quantities (or at minimum, not guaranteed to be in `[0,1]`). The quorum threshold is `3/4` (a relative fraction). Comparing them directly produces a systematically wrong result:

- **If absolute stake values are >> 1** (as they would be in lovelace): `stake >= 3/4` is trivially true for any single voter, so **a single peer vote immediately forges a certificate** regardless of the voter's actual share of committee stake. This is an unauthorized Peras certificate acceptance, directly boosting a block's chain weight and corrupting chain selection.
- **If absolute stake values are << 1** (e.g., fractions of total supply): quorum is never reached, permanently preventing any Peras certificate from being forged and disabling the Peras boost mechanism entirely.

Either outcome breaks the Peras voting and certificate check invariant. The first case is the more dangerous: it allows an unprivileged peer to cause a node to forge and accept a certificate for any block with a single vote, bypassing the quorum requirement entirely.

---

### Likelihood Explanation

The entry path is fully reachable by any unprivileged peer. Peras votes are received via the object diffusion mini-protocol, processed by `processVotes`, validated by `validatePerasVote` (which assigns the raw stake), and then fed into `updatePerasRoundVoteStates` / `votesReachQuorum`. No special privileges, keys, or stake majority are required. The bug is triggered by the normal operation of sending a valid Peras vote. The code comment confirms the issue is known but unresolved.

---

### Recommendation

Before calling `stakeAboveThreshold`, normalize `PerasVoteStake` to a relative value by dividing by the total stake of the voting committee. Concretely, `stakeAboveThreshold` should either:

1. Accept the total committee stake and normalize internally:
   ```haskell
   stakeAboveThreshold params totalCommitteeStake voteStake =
     (unPerasVoteStake voteStake / totalCommitteeStake) >= quorumThreshold + safetyMargin
   ```
2. Or require callers to pass a pre-normalized `PerasVoteStake` (i.e., already divided by total committee stake) and enforce this via the type system.

The `PerasVoteStakeDistr` population path in `validatePerasVote` should also be updated to store relative (normalized) stake values, consistent with the quorum threshold's units.

---

### Proof of Concept

1. A node receives a single `PerasVote` from an unprivileged peer via the object diffusion mini-protocol.
2. `processVotes` calls `validatePerasVote mkPerasParams stakeDistr vote`.
3. `validatePerasVote` looks up the voter's raw absolute stake from `PerasVoteStakeDistr` and stores it as `vpvVoteStake`.
4. The vote is added to the `PerasVoteDB`; `updateCandidateVoteState` calls `votesReachQuorum cfg [vote]`.
5. `votesReachQuorum` computes `totalVoteStake = vpvVoteStake vote` (a single absolute stake value, e.g., `1_000_000` lovelace).
6. `stakeAboveThreshold` evaluates `1_000_000 >= 3/4 + 2/100`, which is `True`.
7. `forgePerasCert` is called and a `ValidatedPerasCert` is produced, boosting the voted block's chain weight — from a single peer vote, bypassing the quorum requirement. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-143)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-161)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-176)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L603-604)
```haskell
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
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
