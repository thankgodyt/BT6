### Title
Peras Quorum Threshold Bypass via Unit Mismatch in `stakeAboveThreshold` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (sourced from absolute ledger stake) against a relative quorum threshold (`3/4 + 2/100 = 0.77`). Because no normalization is performed, any voter with positive absolute stake (e.g., millions of lovelace) trivially satisfies the check, allowing a single vote from any unprivileged peer to forge a Peras certificate and boost an arbitrary block in chain selection.

### Finding Description

The function `stakeAboveThreshold` in `SupportsPeras.hs` is the sole gate that decides whether accumulated votes have reached the Peras quorum required to forge a certificate:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

The threshold is `perasQuorumStakeThreshold = 3/4` plus `perasQuorumStakeThresholdSafetyMargin = 2/100`, giving an effective threshold of `0.77` — a relative fraction of total stake.

The code itself documents the unit mismatch explicitly:

> **NOTE**: At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake). So, for now you can consider this `Rational` as the best approximation we have at the moment of the concrete type for a relative vote stake that can be compared to the quorum threshold value (also currently a `Rational`).

And the TODO on `stakeAboveThreshold` itself states:

> **TODO**: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally.

In the production path, `PerasVoteStakeDistr` is populated from ledger stake values (`LedgerStake`, which are absolute lovelace amounts — e.g., `1_000_000` or larger). These are passed directly into `validatePerasVote` and stored as `PerasVoteStake` without normalization. When `stakeAboveThreshold` then compares, say, `1_000_000 >= 0.77`, the check trivially passes for any voter with positive stake.

The call chain is:
1. Inbound vote arrives via the object diffusion mini-protocol → `makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB`
2. `validatePerasVote mkPerasParams sd vote` assigns the voter's absolute ledger stake as `vpvVoteStake`
3. Vote is added to the DB; `updateCandidateVoteState` calls `votesReachQuorum cfg voteList`
4. `votesReachQuorum` calls `stakeAboveThreshold cfg totalVoteStake`
5. Since absolute stake >> `0.77`, the check always passes → `forgePerasCert` is called immediately
6. The forged certificate boosts the voted-for block's weight in chain selection [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation

An adversary with any positive stake can send a single `PerasVote` message targeting any block. Because `stakeAboveThreshold` always returns `True` when absolute stake is compared against the relative threshold `0.77`, a certificate is immediately forged for that block. Peras certificates boost a block's chain-selection weight by `perasWeight = 15`. This allows an adversary to make an honest node prefer an adversarially chosen chain over the canonical chain, constituting a **bypass of Peras certificate/quorum validation** and a **chain-selection manipulation** bug.

This matches the allowed impact: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance"* and *"chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical … chain."*

### Likelihood Explanation

The entry path is the object diffusion mini-protocol, which is reachable by any unprivileged peer. The `PerasVoteStakeDistr` is read directly from the ledger's absolute stake snapshot with no normalization step anywhere in the production code path. The bug is active whenever Peras voting is enabled. Any peer with a registered stake pool (positive `LedgerStake`) can exploit this with a single crafted vote message.

### Recommendation

Normalize `PerasVoteStake` to a relative value (divide each voter's absolute stake by the total stake in the distribution) before calling `stakeAboveThreshold`, or change `stakeAboveThreshold` to accept the full `PerasVoteStakeDistr` and perform normalization internally. The quorum threshold and the vote stake must be expressed in the same units (both relative fractions in `[0,1]`) for the comparison to be meaningful.

### Proof of Concept

Given `mkPerasParams` defaults:
- `perasQuorumStakeThreshold = 3/4`
- `perasQuorumStakeThresholdSafetyMargin = 2/100`
- Effective threshold = `0.77`

An adversary with a stake pool holding `1_000_000` lovelace (absolute) submits one vote. The `PerasVoteStakeDistr` entry for their pool ID is `PerasVoteStake (1_000_000 % 1)`. In `stakeAboveThreshold`:

```
stake           = 1000000 % 1
quorumThreshold = 3 % 4
safetyMargin    = 2 % 100
1000000 >= 0.77  →  True
```

`votesReachQuorum` returns `Just votesWithQuorum`, `forgePerasCert` is called, and a certificate boosting the adversary's chosen block by weight 15 is immediately produced and stored — with only one vote, from a single peer, regardless of actual stake distribution. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
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
