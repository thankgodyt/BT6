### Title
Peras Quorum Check Compares Incommensurable Stake Units, Enabling Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (which may carry absolute ledger stake) against a `PerasQuorumStakeThreshold` that is defined as a relative fraction (e.g. `3/4`). The code itself documents this unit mismatch as an unresolved TODO. When the stake distribution supplied to `validatePerasVote` contains absolute values, any voter with even minimal stake satisfies `stake >= 0.77`, causing every single vote to immediately reach quorum and forge a certificate — a direct bypass of the Peras quorum check.

### Finding Description

`stakeAboveThreshold` performs the comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The quorum threshold is a relative `Rational` (default `3/4`): [2](#0-1) 

The `PerasVoteStake` type carries an explicit note that no decision has been made on whether it holds absolute or relative stake: [3](#0-2) 

And `stakeAboveThreshold` itself carries a TODO acknowledging the unit assumption is unverified: [4](#0-3) 

`validatePerasVote` assigns `vpvVoteStake` directly from whatever value is stored in the supplied `PerasVoteStakeDistr`, with no normalization: [5](#0-4) 

The production vote-processing path (`makePerasVotePoolWriterFromChainDB`) passes the raw `PerasVoteStakeDistr` obtained from an STM action directly into `validatePerasVote`: [6](#0-5) 

The validated vote's stake is then summed and passed to `stakeAboveThreshold` inside `votesReachQuorum`: [7](#0-6) 

This is the exact structural analog of the Alchemix bug: `inputAmount` (absolute token-A units) is used as `minimumAmountOut` (token-B units). Here, absolute ledger stake (a large integer expressed as a `Rational`) is compared against a relative quorum threshold (a fraction between 0 and 1).

### Impact Explanation

**Case 1 — absolute stake values in the distribution (the dangerous case):** If `PerasVoteStakeDistr` is populated with raw lovelace-denominated stake (e.g. a voter with 1 ADA has stake `1_000_000`), then `1_000_000 >= 0.77` is trivially true. A single vote from any stakeholder — regardless of how small their actual share of total stake is — immediately satisfies the quorum check, causing `votesReachQuorum` to return `Just` and `forgePerasCert` to be called. The resulting `ValidatedPerasCert` is accepted by the ChainDB and can boost an arbitrary block, bypassing the Peras quorum requirement entirely.

**Case 2 — absolute stake values smaller than the threshold:** If stake values are fractional but not normalized to the committee (e.g. a voter with 0.001% of total stake has `PerasVoteStake 0.00001`), quorum can never be reached, permanently breaking certificate production. This is the "unintended revert" analog from the Alchemix report.

The security-relevant case is Case 1: an unprivileged peer who is a legitimate (even minimal) stakeholder can forge a Peras certificate for any block of their choosing, causing that block to receive a `PerasWeight` boost in chain selection. This is a bypass of Peras voting/certificate checks.

### Likelihood Explanation

The TODO comment and the `PerasVoteStake` note are explicit developer acknowledgements that the normalization step is missing and the unit contract is unverified. The `PerasVoteStakeDistr` is populated from the ledger stake distribution, which natively holds absolute stake. The production code path (`makePerasVotePoolWriterFromChainDB`) does not perform any normalization before passing the distribution to `validatePerasVote`. Peras is not yet enabled on mainnet (`eraPerasRoundLength = HardFork.NoPerasEnabled`), which limits immediate exploitability, but the code is in the production library and will be activated in a future hard fork. [8](#0-7) 

### Recommendation

1. Decide on the canonical unit for `PerasVoteStake` (relative fraction of total committee stake is the correct choice given the quorum threshold is relative).
2. Enforce normalization at the point where `PerasVoteStakeDistr` is constructed from the ledger stake distribution, before it is passed to `validatePerasVote`.
3. Alternatively, change `stakeAboveThreshold` to accept the total stake distribution and perform normalization internally, removing the implicit unit assumption.
4. Add a type-level or runtime invariant (e.g. assert `sum (Map.elems distr) <= 1`) to catch future regressions.

### Proof of Concept

Assume `PerasVoteStakeDistr` is populated with absolute lovelace values (1 ADA = 1,000,000 lovelace expressed as `Rational`):

```
voter A has 1 ADA → PerasVoteStake (1_000_000 % 1)

stakeAboveThreshold mkPerasParams (PerasVoteStake (1_000_000 % 1))
  = 1_000_000 >= (3/4 + 2/100)
  = 1_000_000 >= 0.77
  = True   ← quorum reached with a single vote
```

A peer sends one `PerasVote` for an adversarial block. `processVotes` calls `validatePerasVote`, which looks up the voter's stake (1,000,000) from the distribution and stores it in `vpvVoteStake`. `updatePerasRoundVoteStates` calls `updateCandidateVoteState`, which calls `votesReachQuorum`, which calls `stakeAboveThreshold` with the total stake of 1,000,000. The check passes, `forgePerasCert` is called, and a `ValidatedPerasCert` boosting the adversarial block is accepted by the ChainDB — with no honest quorum having been reached. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-176)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
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
