### Title
Missing Stake Normalization in Peras Quorum Check Enables Certificate Forgery Bypass - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (sourced from the ledger's absolute stake distribution) directly against `perasQuorumStakeThreshold` (a relative fraction, e.g. `3/4`), without normalizing the vote stake to the same unit. The code's own TODO comment acknowledges this mismatch. The result is that the quorum check is always trivially satisfied by any single vote carrying absolute lovelace, allowing an unprivileged peer to trigger certificate forging for an arbitrary block with a single crafted vote message.

---

### Finding Description

**Root cause — `stakeAboveThreshold` in `SupportsPeras.hs`:** [1](#0-0) 

The function performs a bare `>=` comparison between `unPerasVoteStake voteStake` and `unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params) + safetyMargin`. The code's own comment explicitly states the precondition is violated:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

**The threshold is a relative fraction:**

`perasQuorumStakeThreshold` is set to `3/4` and `perasQuorumStakeThresholdSafetyMargin` to `2/100`, giving a combined threshold of `0.77`. [2](#0-1) [3](#0-2) 

**The vote stake is absolute lovelace:**

`PerasVoteStake` is populated by `lookupPerasVoteStake`, which reads directly from `PerasVoteStakeDistr` — a map populated from the ledger's absolute stake values. The comment on `PerasVoteStake` itself confirms the conversion from absolute to relative is unresolved and not yet implemented: [4](#0-3) 

**The comparison is performed in `votesReachQuorum`:** [5](#0-4) 

And again in `updateLoserVoteState`: [6](#0-5) 

**The entry path is the object diffusion mini-protocol:**

Votes arrive from unprivileged peers via `makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB`, which call `validatePerasVote mkPerasParams sd vote` and then feed the result into the aggregation pipeline that calls `votesReachQuorum` → `stakeAboveThreshold`. [7](#0-6) 

---

### Impact Explanation

When `PerasVoteStake` carries an absolute lovelace value (e.g., `1_000_000_000_000` for 1 million ADA), the comparison `1_000_000_000_000 >= 0.77` is trivially `True`. A single vote from any registered stake pool immediately satisfies `votesHaveEnoughStake`, causing `votesReachQuorum` to return `Just votesWithQuorum` and `forgePerasCert` to be called. The resulting `ValidatedPerasCert` is accepted into the ChainDB and used to boost the attacker's chosen block in chain selection via `PerasWeight`.

This is a **critical bypass of Peras certificate/vote verification**: the quorum requirement (designed to require ≥ 3/4 of total committee stake) is completely circumvented. An unprivileged peer controlling any registered stake pool can forge a certificate for any block of their choosing with a single crafted vote message, directly manipulating chain selection.

---

### Likelihood Explanation

Any node participating in the Peras vote diffusion network can send a `PerasVote` message. No special privileges, key compromise, or stake majority is required — only a valid registered stake pool key (needed to pass `lookupPerasVoteStake`). The attack is deterministic and requires a single network message.

---

### Recommendation

`stakeAboveThreshold` must normalize `PerasVoteStake` to a relative fraction before comparing it against the threshold. The total stake of the voting committee must be passed in (or computed internally) so that:

```haskell
relativeStake = unPerasVoteStake voteStake / totalCommitteeStake
relativeStake >= quorumThreshold + safetyMargin
```

Alternatively, store `PerasVoteStake` as a pre-normalized relative value at the point of construction in `validatePerasVote`, dividing the voter's absolute ledger stake by the total active stake before inserting it into `PerasVoteStakeDistr`.

---

### Proof of Concept

Assume:
- Stake pool P holds 1,000,000 ADA = `1_000_000_000_000` lovelace
- `perasQuorumStakeThreshold = 3/4`, `perasQuorumStakeThresholdSafetyMargin = 2/100`
- P's entry in `PerasVoteStakeDistr` is `PerasVoteStake (1_000_000_000_000 % 1)`

P sends one `PerasVote` for block B. After `validatePerasVote` succeeds (stake lookup passes), `votesReachQuorum` is called:

```
totalVoteStake = PerasVoteStake (1_000_000_000_000 % 1)
stakeAboveThreshold:
  stake          = 1_000_000_000_000
  quorumThreshold = 3/4
  safetyMargin    = 2/100
  1_000_000_000_000 >= 77/100  →  True
```

`votesReachQuorum` returns `Just`, `forgePerasCert` is called, and a `ValidatedPerasCert` boosting block B is accepted — with only one vote, from a single pool, regardless of total network stake. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-151)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
  deriving stock Generic
  deriving Show via Quiet PerasVoteStake
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L93-98)
```haskell
-- | Total stake needed to forge a Peras certificate.
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L600-606)
```haskell
updateLoserVoteState cfg vote oldState =
  assert (getPerasVoteTarget vote == ptvtTarget (ptvsVoteTally oldState)) $ do
    let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally
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
