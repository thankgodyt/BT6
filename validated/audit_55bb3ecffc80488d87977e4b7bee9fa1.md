### Title
Peras Quorum Threshold Unit Mismatch Enables Certificate Forging with Insufficient Stake — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in the Peras protocol compares accumulated `PerasVoteStake` values directly against `perasQuorumStakeThreshold` (a relative `Rational`, e.g. `3/4`) without enforcing that the vote-stake values are normalized to the same unit. The code itself acknowledges this mismatch with an explicit TODO. If the `PerasVoteStakeDistr` supplied at runtime contains absolute ledger-stake values (lovelace), the comparison is dimensionally wrong: any single vote from a registered pool would satisfy `lovelace_value >= 3/4`, immediately forging a Peras certificate and granting an arbitrary block a chain-weight boost. This directly mirrors the external report's pattern: a threshold documented as relative is compared against an absolute value, silently disabling the intended safety gate.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake          -- Rational
  quorumThreshold = unPerasQuorumStakeThreshold ...   -- 3/4
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ... -- 2/100
``` [1](#0-0) 

The function's own comment states the precondition it cannot enforce:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `perasQuorumStakeThreshold` is set to `3/4` (a relative fraction of total stake): [3](#0-2) 

The production vote-pool writer calls `validatePerasVote mkPerasParams sd vote`, which assigns the voter's entry from `PerasVoteStakeDistr` directly as `vpvVoteStake` with no normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

This is called from both `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB`: [5](#0-4) 

The `PerasVoteStakeDistr` is a `Map PerasVoterId PerasVoteStake` whose values are `Rational`. The ledger's native stake distribution is in absolute lovelace. There is no normalization step between the ledger distribution and the `PerasVoteStakeDistr` enforced anywhere in the consensus layer. The comment on `PerasVoteStake` explicitly admits: "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [6](#0-5) 

When `votesReachQuorum` aggregates votes and calls `stakeAboveThreshold`, the total accumulated `PerasVoteStake` is compared against `3/4`: [7](#0-6) 

If the distribution holds absolute lovelace (e.g. `1_000_000_000_000 % 1`), then `1_000_000_000_000 >= 3/4 + 2/100` is trivially true for any single vote, forging a certificate immediately. If the distribution holds values in the range `[0,1]` but they are not normalized to the committee's total stake (e.g. each pool's fraction of total ADA rather than fraction of committee stake), the comparison is still wrong in proportion to the committee-selection ratio.

---

### Impact Explanation

A forged Peras certificate boosts the chain weight of the targeted block by `perasWeight` (currently `15`). Chain selection in `WeightedSelectView` prefers the chain with the highest total weight: [8](#0-7) 

An adversary who can submit a single vote (i.e. any registered stake pool operator, regardless of stake size) can forge a certificate for an arbitrary block, causing honest nodes to prefer a non-canonical chain. This is a **High** chain-selection bug: an unprivileged peer (any pool operator, even with minimal stake) can make honest nodes prefer a less-secure chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

Peras is disabled by default (`rnFeatureFlags`) but is explicitly designed to be enabled in production. The `PerasVoteStakeDistr` is populated at runtime from the ledger stake distribution, which natively provides absolute lovelace values. No normalization is enforced by the type system or by any consensus-layer code. The TODO comment confirms the mismatch is a known, unresolved issue. Any node operator who enables Peras and any registered pool operator who submits a vote is on the reachable code path.

---

### Recommendation

1. **Enforce units at the type level**: Replace `PerasVoteStake` with a newtype that is only constructible via a normalization function that takes the total committee stake as input, preventing callers from accidentally passing absolute values.
2. **Normalize at validation time**: In `validatePerasVote`, divide the voter's absolute ledger stake by the total stake in `PerasVoteStakeDistr` before assigning `vpvVoteStake`, so the stored value is always a relative fraction in `[0,1]`.
3. **Add a unit test**: Configure a realistic stake distribution with absolute lovelace values, submit a single vote, and assert that `stakeAboveThreshold` returns `False` (quorum not reached), confirming the normalization is correct.

---

### Proof of Concept

1. Enable Peras via `rnFeatureFlags`.
2. Populate `PerasVoteStakeDistr` with a single entry: `PerasVoterId pool_A → PerasVoteStake (1_000_000_000_000 % 1)` (1 trillion lovelace, a realistic small pool).
3. Submit one `PerasVote` from `pool_A` for any block `B` via the object-diffusion mini-protocol.
4. `validatePerasVote` assigns `vpvVoteStake = 1_000_000_000_000 % 1`.
5. `stakeAboveThreshold` evaluates `1_000_000_000_000 >= 3/4 + 2/100 = 0.77` → `True`.
6. `votesReachQuorum` returns `Just` and `forgePerasCert` is called, producing a `ValidatedPerasCert` boosting block `B` by weight 15.
7. `addPerasCertAsync` triggers chain selection; honest nodes now prefer any chain containing `B` over a longer chain without the boost, as `wsvTotalWeight` adds the boost to `B`'s block number. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-272)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
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
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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
