### Title
Peras Quorum Check Compares Absolute Vote Stake Against Relative Threshold Without Normalization - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` directly compares the accumulated `PerasVoteStake` (sourced from the ledger's absolute stake distribution) against `PerasQuorumStakeThreshold` (a relative value, e.g. `3/4`) without any unit normalization. The code itself acknowledges this mismatch in a TODO comment. Because the two quantities are in different scales, the quorum gate that controls Peras certificate forging is broken: a single vote carrying an absolute lovelace-scale stake value will always exceed the relative threshold, allowing any eligible voter to unilaterally forge a certificate and boost an adversary-chosen block's chain weight.

### Finding Description

`PerasVoteStake` is defined as a `Rational` and is populated by looking up a voter's entry in `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [1](#0-0) 

The `PerasVoteStakeDistr` is supplied at runtime from the ledger stake distribution, which naturally holds **absolute** lovelace values. The `PerasVoteStake` type's own comment admits the unit is unresolved:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [2](#0-1) 

`stakeAboveThreshold` then compares the raw accumulated `PerasVoteStake` directly against `PerasQuorumStakeThreshold` (default `3/4`) plus `PerasQuorumStakeThresholdSafetyMargin` (default `2/100`), i.e. a threshold of `0.77`:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [3](#0-2) 

The function's own TODO comment explicitly flags the unit assumption:

> "TODO: this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … Under the current implementation of 'PerasParams', this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [4](#0-3) 

`stakeAboveThreshold` is the sole gate used by `votesReachQuorum`, which is the function that decides whether to forge a Peras certificate:

```haskell
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [5](#0-4) 

`votesReachQuorum` is called inside `updateCandidateVoteState`, which is the core of the vote aggregation state machine: [6](#0-5) 

The production vote ingestion path (`makePerasVotePoolWriterFromChainDB`) passes the raw `PerasVoteStakeDistr` from an STM cell directly into `validatePerasVote` with no normalization step:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [7](#0-6) 

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute lovelace values (the natural ledger representation), then any voter whose absolute stake exceeds `0.77` lovelace — effectively every active stake pool — will satisfy `stakeAboveThreshold` with a **single vote**. This means:

1. A single crafted `PerasVote` from any eligible voter causes `votesReachQuorum` to return `Just`, immediately forging a Peras certificate for the attacker's chosen block.
2. The forged certificate is stored and applied to chain selection via `WeightedSelectView`, boosting the adversary's block by `perasWeight = 15` in `wsvTotalWeight`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [8](#0-7) 

3. Honest nodes running `preferCandidate` will switch to the adversary's chain because its `wsvTotalWeight` is inflated by the illegitimate boost, causing a chain selection error that diverges from the canonical chain.

This is a **High** impact finding: a chain selection bug triggered by an unprivileged peer sending a single vote, causing honest nodes to prefer a non-canonical chain.

### Likelihood Explanation

The entry path is fully reachable by any unprivileged peer via the Peras vote diffusion mini-protocol. The attacker only needs to be a registered stake pool (to appear in `PerasVoteStakeDistr`) and send one `PerasVote` message. No key compromise, stake majority, or admin access is required. The mismatch is structural and present in every call to `stakeAboveThreshold` in the production code path.

### Recommendation

Normalize `PerasVoteStake` to a relative (fractional) value before it is stored in `ValidatedPerasVote`. Specifically, `validatePerasVote` should divide the voter's absolute stake by the total stake in `PerasVoteStakeDistr` before assigning `vpvVoteStake`, so that the accumulated total passed to `stakeAboveThreshold` is always in `[0, 1]` and directly comparable to `PerasQuorumStakeThreshold`. Alternatively, change `stakeAboveThreshold` to accept the total stake and perform normalization internally, eliminating the implicit unit assumption.

### Proof of Concept

1. Node A is a registered stake pool with absolute stake `S` (e.g., `S = 1_000_000` lovelace) in `PerasVoteStakeDistr`.
2. Node A sends a single `PerasVote` for an adversary-chosen block `B_adv` in round `R`.
3. `processVotes` calls `validatePerasVote mkPerasParams stakeDistr vote`, which looks up `S` and stores it as `vpvVoteStake = PerasVoteStake (1_000_000 % 1)`.
4. `updateCandidateVoteState` calls `votesReachQuorum cfg [vote]`, which computes `totalVoteStake = 1_000_000` and calls `stakeAboveThreshold params (PerasVoteStake 1_000_000)`.
5. `stakeAboveThreshold` evaluates `1_000_000 >= 3/4 + 2/100 = 0.77` → `True`.
6. A `ValidatedPerasCert` is forged for `B_adv` with `vpcCertBoost = PerasWeight 15`.
7. The certificate is added to the `PerasWeightSnapshot`; `weightedSelectView` computes `wsvTotalWeight` for any chain containing `B_adv` as `blockNo + 15`, making it heavier than the honest chain by 15 units.
8. `preferCandidate` on honest nodes returns `ShouldSwitch`, causing them to adopt the adversary's chain. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
