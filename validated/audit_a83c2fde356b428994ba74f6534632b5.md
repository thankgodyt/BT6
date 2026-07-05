### Title
Unit Mismatch in Peras Quorum Threshold Check Allows Unauthorized Certificate Creation - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares `PerasVoteStake` (a `Rational` that may carry absolute ledger stake) directly against `PerasQuorumStakeThreshold` (a relative fraction, e.g. `3/4`), without any normalization step. The function's own TODO comment acknowledges the assumption is unenforceable. This is the direct analog of the reported bug: a validation check uses a value in one unit while the input arrives in a different unit, making the check either trivially satisfied or permanently unsatisfiable.

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` is the sole gate that decides whether a Peras voting round has reached quorum and a certificate should be forged:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake          -- Rational
  quorumThreshold = unPerasQuorumStakeThreshold ...   -- 3/4
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ... -- 2/100
``` [1](#0-0) 

The comment immediately above the function states the precondition explicitly:

> *"TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."* [2](#0-1) 

`PerasVoteStake` is populated by `validatePerasVote`, which simply copies whatever `Rational` value is stored in the caller-supplied `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

The ledger's natural stake representation is absolute (lovelace). If `PerasVoteStakeDistr` is populated from the ledger without normalization — which is the natural path, since no normalization helper exists — then `vpvVoteStake` carries an absolute value such as `1_000_000_000_000` (1 ADA in lovelace). The comparison `1_000_000_000_000 >= 3/4 + 2/100` is trivially `True`, so **quorum is declared reached after the very first vote from any registered stake pool**, regardless of that pool's actual share of total stake.

`stakeAboveThreshold` is called in every quorum-decision path:

- `votesReachQuorum` → `updateCandidateVoteState` → `updatePerasRoundVoteState` → `updatePerasRoundVoteStates`
- `updateLoserVoteState` (integrity guard that should prevent a second winner) [4](#0-3) 

The default `PerasParams` sets `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`: [5](#0-4) 

### Impact Explanation

When `PerasVoteStake` carries absolute lovelace values, `stakeAboveThreshold` always returns `True`. A single vote from any registered stake pool immediately triggers `forgePerasCert`, producing a `ValidatedPerasCert` with `vpcCertBoost = perasWeight` (default: 15 virtual blocks). That certificate is stored in the `PerasVoteDB` and applied to chain selection, causing the node to add 15 to the effective length of the boosted chain. An adversarial stake pool can therefore:

1. Send one vote for any block of their choice.
2. Force the local node to treat that block's chain as 15 blocks longer than it actually is.
3. Cause the node to switch to an adversarially chosen fork, violating chain-selection safety.

This matches the **High** impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The inverse failure (absolute values much smaller than `3/4`, e.g. if stake is expressed as a fraction of total supply in a different denominator) would make quorum permanently unreachable, silently disabling Peras's security boost entirely.

### Likelihood Explanation

Any registered stake pool operator can send a Peras vote message. The `validatePerasVote` gate only checks that the voter's key appears in `PerasVoteStakeDistr`; it does not verify the vote's cryptographic signature in the current degenerate instance. The unit mismatch is triggered automatically by the normal ledger-to-consensus stake-distribution handoff if that handoff does not normalize values. The TODO comment confirms no normalization is currently performed.

### Recommendation

`stakeAboveThreshold` must not be called with unnormalized stake. The fix mirrors the mitigation in the external report — enforce the correct unit at the boundary:

```haskell
-- Option A: normalize inside stakeAboveThreshold
stakeAboveThreshold :: PerasParams -> PerasVoteStakeDistr -> PerasVoteStake -> Bool
stakeAboveThreshold params distr voteStake =
  normalizedStake >= quorumThreshold + safetyMargin
 where
  totalStake       = sum (unPerasVoteStakeDistr distr)
  normalizedStake  = unPerasVoteStake voteStake / totalStake
  ...

-- Option B: normalize at the point where PerasVoteStakeDistr is built
-- (divide each pool's absolute stake by the total active stake before
--  storing it in the distribution map)
```

The TODO comment at lines 136–161 of `SupportsPeras.hs` already describes both options. Whichever is chosen, the normalization must happen before `stakeAboveThreshold` is called, and a property test should assert that `stakeAboveThreshold params distr (totalStake distr) == True` and `stakeAboveThreshold params distr mempty == False`.

### Proof of Concept

```haskell
-- Construct a stake distribution with one pool holding 1 ADA (absolute lovelace)
let oneADA     = PerasVoteStake (1_000_000 % 1)   -- 1 ADA in lovelace
    distr      = PerasVoteStakeDistr (Map.singleton someVoterId oneADA)
    params     = mkPerasParams  -- quorumThreshold = 3/4, safetyMargin = 2/100

-- A single vote from that pool
let vote       = ValidatedPerasVote { vpvVote = someVote, vpvVoteStake = oneADA }

-- stakeAboveThreshold returns True immediately:
-- 1_000_000 >= 3/4 + 2/100  ≡  True
assert (stakeAboveThreshold params oneADA)

-- votesReachQuorum therefore returns Just, forging a certificate
-- with a single vote regardless of actual stake proportion:
let Just cert = votesReachQuorum params [vote]
-- cert boosts the adversary's chosen block by perasWeight = 15 virtual blocks
``` [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L569-607)
```haskell
updateCandidateVoteState ::
  StandardHash blk =>
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Candidate ->
  Either
    (PerasForgeErr blk)
    (PerasVoteStateCandidateOrWinner blk)
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

-- | Add a vote to an existing target vote state if it isn't already present.
--
-- PRECONDITION: the vote's target must match the underlying tally's target.
--
-- May fail if the loser goes above quorum by adding the vote.
updateLoserVoteState ::
  StandardHash blk =>
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Loser ->
  Either (PerasTargetVoteState blk 'Loser) (PerasTargetVoteState blk 'Loser)
updateLoserVoteState cfg vote oldState =
  assert (getPerasVoteTarget vote == ptvtTarget (ptvsVoteTally oldState)) $ do
    let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
