### Title
Peras Quorum Check Compares Absolute Stake Against Normalized Threshold Without Unit Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (which is populated from the ledger's absolute stake distribution) directly against `perasQuorumStakeThreshold` (a normalized `Rational` fraction such as 0.75), with no normalization or unit-validation step. The function itself carries an explicit TODO acknowledging this unit mismatch. An unprivileged peer can send a single Peras vote over the node-to-node object-diffusion mini-protocol; because any non-zero absolute lovelace value vastly exceeds the normalized threshold, quorum is immediately triggered and a Peras certificate is forged for an adversary-chosen block.

---

### Finding Description

`stakeAboveThreshold` is defined as:

```haskell
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
``` [1](#0-0) 

The `PerasVoteStake` type is a bare `Rational` with no enforced normalization invariant:

```haskell
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational }
``` [2](#0-1) 

The companion note in the same file explicitly states there is no agreed-upon normalization step:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [3](#0-2) 

`validatePerasVote` stores the raw value from `PerasVoteStakeDistr` directly into `ValidatedPerasVote.vpvVoteStake` without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [4](#0-3) 

`votesReachQuorum` then sums those raw stakes and passes the total directly to `stakeAboveThreshold`:

```haskell
totalVoteStake    = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [5](#0-4) 

`stakeAboveThreshold` is also called in `updateLoserVoteState` inside `Aggregation.hs`, where the same unit mismatch applies:

```haskell
aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
``` [6](#0-5) 

The `PerasVoteStakeDistr` is supplied to the vote-processing pipeline via `getStakeDistrSTM`, which is wired up in both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` — the production node-to-node object-diffusion writers:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [7](#0-6) 

The quorum threshold in `PerasParams` is documented as a fraction of total stake (e.g., > 3/4): [8](#0-7) 

---

### Impact Explanation

`perasQuorumStakeThreshold` is a normalized `Rational` (e.g., `0.75`). Absolute ledger stake values are measured in lovelace (e.g., `1_000_000`). The comparison `1_000_000 >= 0.75 + ε` is trivially `True`. Therefore:

- A **single vote** from any voter with non-zero ledger stake immediately satisfies `votesHaveEnoughStake`, causing `votesReachQuorum` to return `Just` and `forgePerasCert` to be called.
- The forged `ValidatedPerasCert` is stored in the `PerasRoundVoteState` and propagated to the `ChainDB` via `addPerasVoteWithAsyncCertHandling`.
- Peras certificates boost blocks in chain selection (`compareAnchoredFragments` / `forksAtMostKWeight`). A certificate forged for an adversary-chosen block causes the node to prefer the adversarial chain, breaking chain selection.

This is a **bypass of Peras certificate/vote verification** that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is wired into the node-to-node layer. Any connected peer can send a `PerasVote` message. No special privileges, keys, or stake majority are required. The only precondition is that the sender's `PerasVoterId` appears in the node's current `PerasVoteStakeDistr` with a non-zero entry — a condition satisfied by any registered stake pool. The Peras feature is under active development and not yet deployed on mainnet, but the code is in production files and the vulnerability is present in the current codebase.

---

### Recommendation

1. **Normalize before comparison.** Before calling `stakeAboveThreshold`, divide each voter's absolute stake by the total stake in `PerasVoteStakeDistr` to produce a relative value in `[0, 1]`. Alternatively, change `stakeAboveThreshold` to accept the full `PerasVoteStakeDistr` and perform normalization internally, as the TODO suggests.
2. **Enforce units at the type level.** Introduce distinct newtypes for absolute stake (lovelace) and normalized stake (fraction), preventing the two from being mixed in arithmetic or comparisons without an explicit conversion.
3. **Add a precondition assertion.** Until the normalization is implemented, add a runtime assertion in `stakeAboveThreshold` that `unPerasVoteStake voteStake <= 1` to catch the unit mismatch in testing.

---

### Proof of Concept

Assume `perasQuorumStakeThreshold = 0.75` and `perasQuorumStakeThresholdSafetyMargin = 0.01` (typical normalized values). Assume a voter `V` has `1_000_000` lovelace in the ledger, stored as-is in `PerasVoteStakeDistr`.

1. Adversarial peer sends one `PerasVote` for round `R` targeting adversarial block `B_adv`, signed by voter `V`.
2. `processVotes` → `validatePerasVote mkPerasParams stakeDistr vote` → `lookupPerasVoteStake` returns `PerasVoteStake (1_000_000 % 1)`.
3. `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum cfg [validatedVote]`:
   - `totalVoteStake = PerasVoteStake (1_000_000 % 1)`
   - `stakeAboveThreshold cfg totalVoteStake` evaluates `1_000_000 >= 0.75 + 0.01` → `True`
4. `forgePerasCert` is called, producing a `ValidatedPerasCert` boosting `B_adv`.
5. The certificate is stored and used in `compareAnchoredFragments` to prefer the adversarial chain. [1](#0-0) [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-370)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L56-62)
```haskell
--   * The quorum threshold is misconfigured, or that
--   * We were extremely unlucky when randomly selecting the voting committee.
--
-- With a correct threshold configuration (e.g., > 3/4 of total stake + a small
-- safety margin to account for an unlucky local sortition when selecting
-- non-persistent voters during committee selection), multiple winners should be
-- impossible given honest stake distribution.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L569-606)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-200)
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
```
