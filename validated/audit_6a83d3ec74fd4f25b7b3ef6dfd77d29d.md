### Title
Unnormalized `PerasVoteStake` Bypasses Peras Quorum Certificate Check — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` (typed as `Rational`, with no enforced unit) directly against a relative quorum threshold (`3/4 + 2/100`). The function's own TODO comment acknowledges that it assumes both values are in the same normalized units, but `validatePerasVote` performs no normalization and no positivity check before accepting a stake value from the external `PerasVoteStakeDistr`. When the stake distribution is populated with absolute ledger-stake values (lovelace), any single voter with ≥ 1 lovelace satisfies `stake >= 3/4`, forging a certificate with a single vote. This is the direct analog of the Tracer negative-price bypass: a calculated threshold becomes trivially satisfiable due to a unit/sign mismatch in the comparison.

---

### Finding Description

**Root cause — `stakeAboveThreshold` performs no unit validation:**

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake        = unPerasVoteStake voteStake          -- Rational, no unit enforced
  quorumThreshold = unPerasQuorumStakeThreshold ...  -- 3/4 (relative)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ... -- 2/100 (relative)
``` [1](#0-0) 

The code's own comment explicitly flags the invariant that is not enforced:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

**`PerasVoteStake` is an unconstrained `Rational`:**

```haskell
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
``` [3](#0-2) 

No smart constructor, no range check, no sign check. The type admits any `Rational` including negative values and absolute lovelace magnitudes.

**`validatePerasVote` accepts any stake value from the distribution without normalization:**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

The only check is membership in the distribution. The returned `vpvVoteStake` is used verbatim in the quorum tally.

**The quorum check is called directly on the raw accumulated stake:**

In `updateCandidateVoteState`, `votesReachQuorum` is called on the list of `ValidatedPerasVote` values, which sums their `vpvVoteStake` fields via `mconcat` (the `Sum Rational` monoid) and passes the total to `stakeAboveThreshold`: [5](#0-4) [6](#0-5) 

**Network entry point — votes arrive from unprivileged peers:**

`processVotes` in the Peras vote diffusion mini-protocol receives votes from any connected peer, validates them against the `PerasVoteStakeDistr` (obtained via `getStakeDistrSTM`), and adds accepted votes to the `PerasVoteDB`: [7](#0-6) 

The production wiring in `NodeToNode.hs` currently passes `pure (PerasVoteStakeDistr mempty)` as a placeholder, with an explicit TODO to replace it with real ledger stake data: [8](#0-7) 

When that TODO is resolved and the distribution is populated with absolute ledger-stake values (lovelace), the unit mismatch activates: any voter with ≥ 1 lovelace of absolute stake satisfies `1 >= 3/4 + 2/100`, forging a certificate with a single vote.

---

### Impact Explanation

**Severity: High — Bypass of Peras certificate/vote checks enabling unauthorized certificate acceptance.**

A forged `ValidatedPerasCert` is stored in the `PerasVoteDB` and propagated to the `ChainDB`. The `WeightedSelectView` chain-selection logic adds `vpcCertBoost` (default `PerasWeight 15`) to the block's total weight: [9](#0-8) 

An adversary with any positive ledger stake can:
1. Send a single crafted `PerasVote` for their chosen block via the vote diffusion protocol.
2. The vote passes `validatePerasVote` (voter is in the distribution).
3. `stakeAboveThreshold` returns `True` because absolute lovelace ≥ 3/4.
4. A `ValidatedPerasCert` is forged and stored.
5. The adversary's block receives a +15 weight boost in chain selection.
6. Honest nodes prefer the adversarially boosted chain over the canonical chain.

This breaks the Peras safety guarantee that a certificate requires a supermajority (≥ 3/4) of committee stake.

---

### Likelihood Explanation

**Medium-High.** The vulnerability is latent: the current production code uses an empty stake distribution, so no votes are accepted today. However, the TODO at `NodeToNode.hs:402–406` is the only barrier. Once the Peras plumbing is completed and the distribution is populated from the ledger (which is the explicit design intent), the bug activates immediately for any peer that holds any positive stake. The code path is fully wired end-to-end; only the stake distribution source is missing.

---

### Recommendation

1. **Enforce normalization before comparison.** `stakeAboveThreshold` must either (a) accept the total stake distribution and normalize internally, or (b) require that `PerasVoteStake` values are pre-normalized to `[0, 1]` before being stored in `PerasVoteStakeDistr`.

2. **Add a positivity guard in `validatePerasVote`.** Reject any vote whose looked-up stake is `<= 0`:
   ```haskell
   | Just stake <- lookupPerasVoteStake vote stakeDistr
   , unPerasVoteStake stake > 0 = Right ...
   ```

3. **Add a smart constructor for `PerasVoteStakeDistr`** that validates all entries are in `(0, 1]` and sum to ≤ 1, enforcing the relative-stake invariant at construction time rather than at comparison time.

4. **Resolve the unit ambiguity** documented in the TODO at `SupportsPeras.hs:155–161` before connecting the live stake distribution.

---

### Proof of Concept

With the stake distribution populated from ledger data (absolute lovelace):

```
params = mkPerasParams  -- quorumThreshold = 3/4, safetyMargin = 2/100
stakeDistr = PerasVoteStakeDistr (Map.singleton attackerVoterId (PerasVoteStake 1))
  -- 1 lovelace absolute stake

vote = PerasVote { pvVoteRound = r, pvVoteBlock = adversarialBlock, pvVoteVoterId = attackerVoterId }

-- validatePerasVote succeeds: attacker is in distribution
-- vpvVoteStake = PerasVoteStake 1

-- stakeAboveThreshold:
-- stake = 1
-- quorumThreshold + safetyMargin = 3/4 + 2/100 = 77/100
-- 1 >= 77/100  =>  True  ✓  (quorum "reached" with 1 vote)

-- votesReachQuorum returns Just (ValidatedPerasVotesWithQuorum ...)
-- forgePerasCert produces ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }
-- adversarialBlock gains +15 weight in chain selection
``` [10](#0-9) [11](#0-10) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
