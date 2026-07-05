### Title
Peras Quorum Check Compares Absolute Vote Stake Against Relative Threshold Without Normalization - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The Peras vote quorum check in `stakeAboveThreshold` compares a `PerasVoteStake` value (sourced from a `PerasVoteStakeDistr` that may contain absolute ledger stake values) directly against a fixed relative threshold (`perasQuorumStakeThreshold = 3/4`). The code itself documents this as an unresolved unit-mismatch: if the vote stake values are absolute rather than normalized, the comparison is semantically invalid. Depending on the direction of the mismatch, a single vote from any registered stake pool can satisfy quorum (absolute stake >> 0.75), allowing an unprivileged peer to cause the local node to forge a Peras certificate for an adversary-chosen block, directly manipulating chain selection.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the core quorum check for Peras vote aggregation:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake    = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (...)
``` [1](#0-0) 

The code carries an explicit developer warning that the two sides of this comparison must be in the same units (both relative/normalized, or both absolute), and that under the current implementation the threshold is relative but the vote stake may not be:

```
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. ...
-- Under the current implementation of 'PerasParams', this function only
-- makes sense when both values are relative (normalized) values, so we
-- should either normalize the 'PerasVoteStake' before calling this function,
-- or change this function to accept a stake distribution and perform the
-- normalization internally.
``` [2](#0-1) 

The default `mkPerasParams` sets `perasQuorumStakeThreshold = 3/4` (a relative value between 0 and 1): [3](#0-2) 

The vote stake is assigned during `validatePerasVote` by a plain lookup from `PerasVoteStakeDistr` with no normalization step:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

The `PerasVoteStakeDistr` is read from an `STM` action (`getStakeDistrSTM`) whose source is the ledger stake distribution. Ledger stake values are absolute lovelace amounts (e.g., `10^9` to `10^15`). Comparing such values against `0.75` means `stake >= 0.75` is trivially true for every voter, so **a single vote from any registered stake pool immediately satisfies quorum**.

This is used in both production pool writers:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [5](#0-4) [6](#0-5) 

The quorum check is then applied in `votesReachQuorum` → `updateCandidateVoteState` → `updatePerasRoundVoteStates`, which is the path that forges a `ValidatedPerasCert` and triggers chain selection: [7](#0-6) 

---

### Impact Explanation

If `PerasVoteStakeDistr` contains absolute ledger stake values (lovelace), then `unPerasVoteStake voteStake` will be a large integer (e.g., `1_000_000_000`) while `quorumThreshold` is `0.75`. The condition `stake >= 0.75 + 0.02` is always true. Consequently:

- A single vote from any registered stake pool causes `votesReachQuorum` to return `Just`, triggering `forgePerasCert`.
- The forged `ValidatedPerasCert` is stored in the `PerasVoteDB` / `ChainDB` and used to boost the voted-for block in chain selection via `PerasWeightSnapshot`.
- An adversary who controls any stake pool can send a single crafted `PerasVote` pointing to an adversarial block and cause the honest node to boost that block, biasing chain selection away from the canonical chain.

This is a **High** impact chain-selection bug: an unprivileged peer (any registered stake pool operator) can make an honest node prefer a non-canonical chain by injecting a single vote message.

---

### Likelihood Explanation

The entry path is fully reachable from the network: `processVotes` in `PerasVote.hs` is called for every batch of inbound `PerasVote` objects received via the ObjectDiffusion mini-protocol. No special privileges are required beyond being a registered stake pool (which is a public, permissionless action on Cardano). The mismatch is not gated by any feature flag; it is present in the active production code path for both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`. [8](#0-7) 

---

### Recommendation

1. **Normalize vote stakes before comparison.** Before calling `stakeAboveThreshold`, divide each voter's absolute stake by the total stake in `PerasVoteStakeDistr` to produce a relative value in `[0, 1]`. Alternatively, change `stakeAboveThreshold` to accept the total stake and perform normalization internally.

2. **Enforce units at the type level.** Introduce distinct newtypes for absolute and relative stake (analogous to the `Stake Ledger` vs `Stake Weight` distinction already used in the WFALS committee model) so that the compiler rejects comparisons between incompatible units.

3. **Resolve the TODO at issue #120.** The comment and linked issue acknowledge this gap; it should be treated as a security-critical fix before Peras is enabled on any network.

---

### Proof of Concept

Assume `PerasVoteStakeDistr` maps pool key `P` to `PerasVoteStake (1_000_000_000 % 1)` (1 ADA in lovelace as a `Rational`).

```
stakeAboveThreshold mkPerasParams (PerasVoteStake (1_000_000_000 % 1))
= 1_000_000_000 >= (3/4) + (2/100)
= 1_000_000_000 >= 0.77
= True   -- quorum reached with a single vote
```

An adversary controlling pool `P` sends one `PerasVote { pvVoteRound = r, pvVoteBlock = adversarialBlock, pvVoteVoterId = P }` to an honest node. `processVotes` validates it (stake lookup succeeds), `updateCandidateVoteState` calls `votesReachQuorum` which returns `Just`, `forgePerasCert` produces a `ValidatedPerasCert` boosting `adversarialBlock`, and the ChainDB applies the Peras weight to that block in chain selection — all from a single network message.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-111)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
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
