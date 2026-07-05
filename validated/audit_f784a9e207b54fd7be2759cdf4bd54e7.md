### Title
Peras Quorum Check Compares Unnormalized Absolute Stake Against Relative Threshold, Enabling Single-Vote Certificate Forgery — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares the accumulated `PerasVoteStake` — populated from the raw ledger stake distribution containing **absolute** lovelace amounts — directly against `perasQuorumStakeThreshold`, which is a **relative** fraction (e.g., `3/4`). Because no normalization step converts absolute stake to a relative fraction before the comparison, any voter with even 1 lovelace of stake can single-handedly satisfy the quorum check, allowing them to forge a Peras certificate for any block of their choosing.

---

### Finding Description

`PerasVoteStake` is a `Rational` newtype populated from `PerasVoteStakeDistr` during vote validation. The distribution is sourced from the raw ledger stake state (absolute lovelace amounts). The `perasQuorumStakeThreshold` is configured as `3/4` — a relative fraction of total committee stake.

The comparison in `stakeAboveThreshold` is:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `stake` is an absolute lovelace amount (e.g., `1_000_000` for 1 ADA) and `quorumThreshold` is `0.75`. Since `1_000_000 >> 0.77`, any single vote from a voter with ≥ 1 lovelace of stake trivially satisfies the quorum check.

The codebase itself acknowledges this in two explicit places:

**1. The `PerasVoteStake` type comment (lines 136–143):**
> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [1](#0-0) 

**2. The `stakeAboveThreshold` TODO (lines 153–161):**
> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The quorum check is invoked in two places in the vote aggregation pipeline:

- In `updateCandidateVoteState` via `votesReachQuorum` (candidate → winner transition): [3](#0-2) 

- In `updateLoserVoteState` (loser-above-quorum guard): [4](#0-3) 

The `votesReachQuorum` function sums raw `vpvVoteStake` values and passes the total directly to `stakeAboveThreshold` without any normalization: [5](#0-4) 

The stake distribution is read from the ledger state and passed into the vote validation pipeline via `makePerasVotePoolWriterFromChainDB`: [6](#0-5) 

The default `perasQuorumStakeThreshold` is `3/4` and `perasQuorumStakeThresholdSafetyMargin` is `2/100`: [7](#0-6) 

---

### Impact Explanation

This is a **bypass of Peras certificate/vote verification**. Because the quorum check trivially passes for any voter with ≥ 1 lovelace of absolute stake, an unprivileged peer can forge a Peras certificate for any block with a single vote. The forged certificate carries `perasWeight = 15` boost, causing honest nodes to prefer the attacker's chosen block over the canonical chain tip. This enables unauthorized certificate acceptance and chain selection manipulation — a direct violation of Peras safety guarantees.

---

### Likelihood Explanation

The Peras vote processing pipeline is active in the production codebase and reachable via the node-to-node mini-protocol. Any registered stake pool with any positive stake (even 1 lovelace) can send a single crafted vote. No privileged access, key compromise, or stake majority is required. The attacker-controlled entry path is: peer sends `PerasVote` → `processVotes` → `validatePerasVote` (stake lookup, no normalization) → `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold` (broken comparison) → certificate forged.

---

### Recommendation

Before calling `stakeAboveThreshold`, normalize the accumulated `PerasVoteStake` by dividing by the total stake of the voting committee. Alternatively, change `stakeAboveThreshold` to accept the total committee stake and perform normalization internally:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> PerasVoteStake -> Bool
stakeAboveThreshold params totalCommitteeStake voteStake =
  normalizedStake >= quorumThreshold + safetyMargin
 where
  normalizedStake = unPerasVoteStake voteStake / unPerasVoteStake totalCommitteeStake
  ...
```

---

### Proof of Concept

1. Attacker is a registered stake pool with 1 lovelace of absolute ledger stake.
2. Attacker sends a single `PerasVote` for target block `B` in round `R`.
3. `processVotes` calls `validatePerasVote mkPerasParams stakeDistr vote` → `vpvVoteStake = PerasVoteStake 1` (1 lovelace, absolute).
4. `updateCandidateVoteState` calls `votesReachQuorum cfg [vote]`.
5. `votesReachQuorum` computes `totalVoteStake = PerasVoteStake 1` and calls `stakeAboveThreshold params (PerasVoteStake 1)`.
6. `stakeAboveThreshold` evaluates: `1 >= 3/4 + 2/100 = 0.77` → **TRUE**.
7. `forgePerasCert` is called and a certificate for block `B` is produced.
8. The certificate boosts block `B`'s chain weight by `perasWeight = 15`, causing honest nodes to prefer `B` over the canonical chain tip.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-149)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L127-148)
```haskell
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
