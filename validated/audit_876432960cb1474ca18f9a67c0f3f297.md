### Title
`stakeAboveThreshold` Compares Unnormalized Absolute Vote Stake Against Relative Quorum Threshold, Enabling Single-Voter Peras Certificate Forgery - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares the accumulated `PerasVoteStake` — a raw sum of per-voter values looked up from `PerasVoteStakeDistr` — against the quorum threshold stored in `PerasParams`, without any normalization step. The code itself carries an explicit TODO acknowledging that the two quantities must be in the same units, and that the current implementation only makes sense when both are relative (normalized) values. If the stake distribution is populated with absolute ledger stakes (the natural representation from the Cardano ledger), the comparison is between incompatible units, and a single voter whose absolute stake exceeds the quorum threshold value (e.g., any voter with more than 0.75 lovelace when the threshold is `0.75`) can unilaterally forge a Peras certificate, bypassing the quorum requirement entirely.

---

### Finding Description

`PerasVoteStake` is a plain `Rational` with no unit enforcement:

```haskell
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational
``` [1](#0-0) 

The quorum check is:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [2](#0-1) 

The code carries an explicit acknowledgment of the unit mismatch:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [3](#0-2) 

The per-vote stake is assigned during `validatePerasVote` by a direct lookup from `PerasVoteStakeDistr` — no normalization is applied:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [4](#0-3) 

These per-vote stakes are then summed in `votesReachQuorum`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [5](#0-4) 

`votesReachQuorum` is called from `updateCandidateVoteState`, which is the core quorum-check path inside `updatePerasRoundVoteState`: [6](#0-5) 

`updatePerasRoundVoteState` is invoked by `implAddVote` in the production `PerasVoteDB` implementation, which is the live code path reached when a peer submits a vote via the vote diffusion mini-protocol: [7](#0-6) 

The same broken comparison is also used in `updateLoserVoteState` to detect whether a losing target has gone above quorum — meaning the "multiple winners" guard is equally unreliable under the same conditions: [8](#0-7) 

**Analogy to the external report**: The external report's bug uses `safeTransferAllETH` (the total contract balance) instead of `safeTransferETH(to, sleeper_.amount)` (the specific sleeper's amount). Here, the code uses the raw sum of absolute ledger stakes (the "total balance" of all voters' absolute stakes) instead of the normalized relative fraction of committee stake (the "specific amount" each voter contributes toward quorum). In both cases, an aggregate quantity replaces the correct per-item quantity, allowing one party to satisfy a threshold that was designed to require collective participation.

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute ledger stakes (e.g., lovelace values such as `1_000_000` for 1 ADA), the accumulated `PerasVoteStake` after even a single vote will be a large integer, while `perasQuorumStakeThreshold` is a relative value such as `0.75`. The comparison `1_000_000 >= 0.75` is trivially true, so the very first vote received for any target in any round immediately forges a Peras certificate for that target. This is a complete bypass of the quorum requirement: a single unprivileged peer who is a registered voter can unilaterally produce a `ValidatedPerasCert` that the node accepts and propagates, without any collective agreement. This falls squarely within the allowed impact scope: **bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance**.

---

### Likelihood Explanation

**Low.** The Cardano ledger natively tracks stake in absolute units (lovelace). The comment in the code explicitly states there is no agreed-upon normalization procedure, meaning the normalization step is absent rather than merely deferred. Any integration path that feeds raw ledger stake values into `PerasVoteStakeDistr` — the natural and simplest approach — triggers the vulnerability. The Peras protocol is still being integrated, so the distribution is not yet wired to the live ledger on mainnet, which limits current exploitability. However, the code is present in the production library and the flaw will become exploitable as integration proceeds.

---

### Recommendation

Normalization must be enforced before the quorum comparison. Two options:

1. **Normalize at the call site**: Before calling `stakeAboveThreshold`, divide the accumulated `PerasVoteStake` by the total committee stake to obtain a relative fraction.

2. **Normalize inside `stakeAboveThreshold`**: Change the signature to accept the total committee stake and perform the division internally:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> PerasVoteStake -> Bool
stakeAboveThreshold params totalCommitteeStake voteStake =
  normalizedStake >= quorumThreshold + safetyMargin
 where
  normalizedStake = unPerasVoteStake voteStake / unPerasVoteStake totalCommitteeStake
  ...
```

The `PerasVoteStakeDistr` should also carry or be accompanied by the total committee stake so that normalization can be performed consistently wherever vote stakes are used.

---

### Proof of Concept

1. Construct a `PerasVoteStakeDistr` containing a single voter with absolute ledger stake `1_000_000` (1 ADA in lovelace).
2. Set `perasQuorumStakeThreshold = 0.75` and `perasQuorumStakeThresholdSafetyMargin = 0.0` in `PerasParams`.
3. Submit a single `PerasVote` from that voter via the vote diffusion protocol.
4. `validatePerasVote` assigns `vpvVoteStake = PerasVoteStake (1_000_000 % 1)`.
5. `updateTargetVoteTally` accumulates `ptvtTotalStake = 1_000_000`.
6. `votesReachQuorum` calls `stakeAboveThreshold`: `1_000_000 >= 0.75` → `True`.
7. `forgePerasCert` is called and a `ValidatedPerasCert` is produced and stored.
8. The node now holds a Peras certificate forged by a single voter, with no quorum having been reached. [9](#0-8) [10](#0-9) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L144-151)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L448-459)
```haskell
    swapVote =
      Map.insertLookupWithKey
        (\_k old _new -> old)
        (getPerasVoteId vote)

    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-211)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
