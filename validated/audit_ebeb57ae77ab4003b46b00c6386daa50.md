### Title
Peras Quorum Check Compares Absolute Ledger Stake Against Relative Threshold Without Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares a `PerasVoteStake` value (populated from the ledger's absolute lovelace stake distribution) against a `PerasQuorumStakeThreshold` (a relative fraction, e.g. `3 % 4`), without normalizing the vote stake first. This is the exact same class of bug as the external report: a formula that silently assumes both operands share the same unit/scale. The code itself contains a TODO comment explicitly acknowledging the mismatch. The result is that any registered stake pool with any positive absolute stake can forge a Peras certificate for an arbitrary block with a single vote, bypassing the quorum requirement entirely.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the quorum check:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The code's own TODO comment admits the unit mismatch:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

**How `PerasVoteStake` is populated (the absolute side):**

`validatePerasVote` assigns the stake directly from `lookupPerasVoteStake`, which is a plain `Map.lookup` into `PerasVoteStakeDistr` — a map populated from the ledger's raw stake distribution (absolute lovelace values):

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [3](#0-2) 

`lookupPerasVoteStake` is a bare `Map.lookup` with no normalization: [4](#0-3) 

In the production vote-pool writer, `validatePerasVote` is called with `mkPerasParams` and the raw `PerasVoteStakeDistr` obtained from the ledger: [5](#0-4) 

**How `PerasQuorumStakeThreshold` is defined (the relative side):**

`PerasQuorumStakeThreshold` wraps a `Rational` intended to be a relative fraction of total stake (e.g. `3 % 4` for 75%): [6](#0-5) 

**The mismatch in numbers:**

| Value | Example |
|---|---|
| `stake` (absolute lovelace) | `1_000_000_000` (1000 ADA) |
| `quorumThreshold` (relative) | `3 % 4` = 0.75 |
| Comparison | `1_000_000_000 >= 0.75` → **always True** |

Any pool with even 1 lovelace of absolute stake satisfies `1 >= 0.75`, so the quorum check is trivially bypassed.

**The call chain from network input to the broken check:**

A peer sends a `PerasVote` message → `processVotes` → `validatePerasVote` (assigns raw absolute stake) → `addVote` → `updatePerasRoundVoteState` → `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold` (broken comparison). [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**Peras certificate verification bypass / chain selection manipulation.**

A single vote from any registered stake pool (regardless of how small its stake) causes `stakeAboveThreshold` to return `True` because the absolute lovelace value (≥ 1) always exceeds the relative quorum threshold (e.g. 0.75). This means `votesReachQuorum` returns `Just` and `forgePerasCert` is called, producing a `ValidatedPerasCert` for the attacker's chosen block. Peras certificates boost blocks in chain selection (`vpcCertBoost`), so an attacker can make honest nodes prefer an adversarially chosen block over the canonical chain, constituting a chain selection safety failure.

---

### Likelihood Explanation

Any registered stake pool operator — an unprivileged network participant — can trigger this by sending a single well-formed `PerasVote` message to a node running the Peras code path. No key compromise, stake majority, or social engineering is required. The only prerequisite is being a registered pool with any positive stake, which is a normal operational state.

---

### Recommendation

Normalize `PerasVoteStake` to a relative value before calling `stakeAboveThreshold`. Concretely, `stakeAboveThreshold` should accept the total stake of the distribution and divide `unPerasVoteStake voteStake` by it before comparing against `perasQuorumStakeThreshold`. Alternatively, populate `PerasVoteStakeDistr` with pre-normalized (relative) values at the point where the ledger stake distribution is read, so that `PerasVoteStake` is always a fraction in `[0,1]` by construction.

---

### Proof of Concept

Given `mkPerasParams` with `perasQuorumStakeThreshold = 3 % 4` and a pool with 1 lovelace of absolute stake:

1. Pool sends `PerasVote { pvVoteRound = r, pvVoteBlock = adversarialBlock, pvVoteVoterId = poolId }`.
2. `validatePerasVote mkPerasParams stakeDistr vote` looks up `poolId` → finds `PerasVoteStake (1 % 1)` (1 lovelace absolute).
3. `votesReachQuorum` calls `stakeAboveThreshold` with `totalVoteStake = PerasVoteStake (1 % 1)`.
4. `stakeAboveThreshold`: `(1 % 1) >= (3 % 4) + safetyMargin` → `True` (since `1 > 0.75`).
5. `forgePerasCert` is called → `ValidatedPerasCert` is produced for `adversarialBlock`.
6. Chain selection boosts `adversarialBlock` by `perasWeight`, causing honest nodes to prefer it. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L94-98)
```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
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
