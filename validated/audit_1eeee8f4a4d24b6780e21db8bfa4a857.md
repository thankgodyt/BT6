### Title
Peras Quorum Check Compares Potentially Absolute Vote Stake Against Relative Threshold Without Normalization - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` directly compares `PerasVoteStake` (which may carry absolute ledger stake values) against `perasQuorumStakeThreshold` (a relative fraction, e.g. `3/4`) without any normalization step. The code itself documents this as an unresolved unit-mismatch problem. When the real stake distribution is wired in, the comparison will be between incommensurable quantities, causing the quorum gate to either always pass (trivial certificate forging) or never pass (permanent quorum failure), depending on the magnitude of the absolute values.

### Finding Description

`stakeAboveThreshold` in `Ouroboros.Consensus.Block.SupportsPeras` performs the core Peras quorum check:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake     = unPerasVoteStake voteStake          -- Rational, unit unknown
  quorumThreshold = unPerasQuorumStakeThreshold
                      (perasQuorumStakeThreshold params)  -- Rational, relative (3/4)
  safetyMargin = ...                              -- Rational, relative (2/100)
``` [1](#0-0) 

The developers explicitly document the unit ambiguity in the `PerasVoteStake` definition:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake). … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

`PerasVoteStake` is assigned during vote validation by a direct lookup into `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [3](#0-2) 

The `PerasVoteStakeDistr` is populated externally. The committee selection layer (`WFALS`, `EveryoneVotes`) produces `VoteWeight` values that for persistent members equal raw `LedgerStake` (absolute lovelace amounts):

```haskell
implEligiblePartyVoteWeight _committee member =
  VoteWeight (unLedgerStake (unNonZero voterStake))
``` [4](#0-3) 

When the real committee selection data is wired into `PerasVoteStakeDistr` (the production diffusion code currently uses `pure (PerasVoteStakeDistr mempty)` as a placeholder), if absolute lovelace values flow in, a voter with ≥1 lovelace would have `PerasVoteStake (1 % 1) = 1.0`, which satisfies `1.0 >= 3/4 + 2/100 = 0.77`. A single vote from any voter with positive stake would forge a certificate. Conversely, if the total stake is on the order of 45 × 10¹⁵ lovelace and individual stakes are small fractions of that, the sum of all votes would still be far below `3/4`, making quorum permanently unreachable.

The production diffusion handler confirms the placeholder and the intended future wiring:

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
(pure (PerasVoteStakeDistr mempty))
``` [5](#0-4) 

The quorum check is the gate for `votesReachQuorum`, which is called by `updateCandidateVoteState` and `updateLoserVoteState` throughout the vote aggregation pipeline: [6](#0-5) [7](#0-6) 

### Impact Explanation

If absolute stake values flow into `PerasVoteStakeDistr` (the expected path from the committee selection layer), a single vote from any voter with ≥1 lovelace satisfies the `3/4` quorum threshold. An unprivileged peer can send one crafted `PerasVote` message and cause the node to forge a `ValidatedPerasCert` for an arbitrary block, boosting it by `perasWeight` (default: 15 block-lengths). This constitutes a **bypass of Peras certificate/quorum validation**, allowing unauthorized chain-weight manipulation. In the opposite direction (if values are too small), quorum is permanently unreachable, disabling the Peras boosting mechanism entirely.

### Likelihood Explanation

The vulnerability is latent today (the production code uses an empty stake distribution, rejecting all votes). It becomes active the moment the real committee selection data is plumbed in, which is the explicitly stated next step. The root cause is already present in production code and documented by the developers themselves as an unresolved correctness issue. Any unprivileged peer participating in the Peras vote diffusion mini-protocol is the attacker entry point.

### Recommendation

`stakeAboveThreshold` must normalize `PerasVoteStake` to a relative fraction before comparing it to `perasQuorumStakeThreshold`. The function signature should be changed to accept the total stake of the committee (or the full `PerasVoteStakeDistr`) so it can compute `totalVoteStake / totalCommitteeStake >= threshold`. Alternatively, enforce at the point where `PerasVoteStakeDistr` is populated that all values are already normalized relative fractions summing to ≤ 1, and add a type-level or runtime assertion to prevent absolute values from entering the comparison.

### Proof of Concept

1. Node is running with Peras enabled and the real stake distribution wired into `PerasVoteStakeDistr` (absolute lovelace values, e.g. voter A has 1,000,000 lovelace → `PerasVoteStake (1000000 % 1)`).
2. Attacker controls voter A and sends a single `PerasVote` for an adversarial block B via the Peras vote diffusion mini-protocol.
3. `processVotes` calls `validatePerasVote`, which looks up voter A in `PerasVoteStakeDistr` and assigns `vpvVoteStake = PerasVoteStake (1000000 % 1)`.
4. `updatePerasRoundVoteStates` calls `updateCandidateVoteState`, which calls `votesReachQuorum`, which calls `stakeAboveThreshold`.
5. `stakeAboveThreshold` evaluates: `1000000 >= 3/4 + 2/100` → `True`.
6. `forgePerasCert` is called, producing a `ValidatedPerasCert` boosting block B by 15 block-lengths.
7. The certificate is accepted into ChainDB and propagated, causing honest nodes to prefer the adversarial chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L238-245)
```haskell
implEligiblePartyVoteWeight ::
  VotingCommittee crypto EveryoneVotes ->
  EligibilityWitness crypto EveryoneVotes ->
  VoteWeight
implEligiblePartyVoteWeight _committee member =
  VoteWeight (unLedgerStake (unNonZero voterStake))
 where
  EveryoneVotesMember _ voterStake = member
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L400-407)
```haskell
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
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
