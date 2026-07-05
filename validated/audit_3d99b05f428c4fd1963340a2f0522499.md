### Title
Peras Quorum Check Compares Absolute Vote Stake Against Relative Threshold Without Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares a `PerasVoteStake` (which may be an absolute ledger-stake value) against `perasQuorumStakeThreshold` (a relative fraction, e.g. `3/4`). There is no normalization step. The code itself documents this as an unresolved assumption. When the placeholder empty `PerasVoteStakeDistr` is replaced with real ledger stake data, a single voter whose absolute stake value exceeds the relative threshold (e.g. `> 0.75`) can unilaterally forge a Peras certificate, bypassing the quorum requirement entirely.

---

### Finding Description

`PerasQuorumStakeThreshold` is defined as a `Rational` fraction of total committee stake — the default is `3/4`: [1](#0-0) [2](#0-1) 

`PerasVoteStake` is also a bare `Rational`, but its comment explicitly states there is no agreed-upon method to convert absolute ledger stake to the relative value needed for comparison: [3](#0-2) 

`stakeAboveThreshold` performs a raw numeric comparison of these two `Rational` values with no normalization: [4](#0-3) 

The function's own TODO comment acknowledges the unit mismatch:

> *"this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."*

`validatePerasVote` assigns the stake value directly from `PerasVoteStakeDistr` to `vpvVoteStake` without any normalization: [5](#0-4) 

This `vpvVoteStake` is then summed and fed directly into `stakeAboveThreshold` in both `votesReachQuorum`: [6](#0-5) 

and in the `PerasVoteDB` model's `addVote`: [7](#0-6) 

The production diffusion layer currently uses an empty `PerasVoteStakeDistr` as a placeholder, causing all votes to be rejected: [8](#0-7) 

The TODO comments in both the diffusion layer and the vote pool writer confirm this is a known placeholder that will be replaced with real committee selection data: [9](#0-8) 

---

### Impact Explanation

This is a **Critical bypass of Peras certificate/vote verification**. When the placeholder empty `PerasVoteStakeDistr` is replaced with real ledger stake data (the intended next step per the TODO comments), the quorum check will compare mismatched units:

- **Numerator** (`PerasVoteStake`): absolute lovelace or pool-stake value from the ledger (e.g. `1_000_000_000_000`)
- **Denominator** (`perasQuorumStakeThreshold`): a relative fraction (e.g. `3 % 4 = 0.75`)

A single voter whose absolute stake value exceeds `0.75` (trivially true for any pool with non-trivial stake) would satisfy `stakeAboveThreshold` with a single vote, allowing them to unilaterally forge a Peras certificate. This certificate would then be accepted by the chain and grant a `PerasWeight` boost to an arbitrary block, corrupting chain selection for all honest nodes.

Conversely, if stake values are stored as fractions of total supply (all < 1), the sum of all votes could still never reach `3/4 + 2/100 = 0.77`, making quorum permanently unreachable and disabling the Peras protocol entirely.

---

### Likelihood Explanation

The vulnerability is latent but structurally inevitable. The production code explicitly marks the empty stake distribution as a temporary placeholder with a TODO to replace it with real committee selection data. Any implementer who naturally populates `PerasVoteStakeDistr` with absolute ledger stake values (the most natural source) will trigger the bug. The type system provides no protection — both the threshold and the vote stake are bare `Rational` values with no unit annotation. The mismatch is invisible at compile time and at runtime until quorum decisions diverge from expectations.

---

### Recommendation

1. **Enforce units at the type level**: Introduce distinct newtypes for absolute stake (`AbsolutePerasVoteStake`) and relative stake (`RelativePerasVoteStake`), and require `stakeAboveThreshold` to accept only the relative variant.
2. **Normalize at validation time**: `validatePerasVote` should accept the total committee stake and normalize the voter's absolute stake to a relative fraction before constructing `ValidatedPerasVote`.
3. **Alternatively**, change `stakeAboveThreshold` to accept the full `PerasVoteStakeDistr` and compute the total stake internally, performing normalization before comparison.
4. **Remove the placeholder**: The empty `PerasVoteStakeDistr` in `NodeToNode.hs` should be replaced with the actual committee selection data before Peras is enabled in production.

---

### Proof of Concept

Assume the real committee selection populates `PerasVoteStakeDistr` with absolute lovelace stake:

```
PerasVoteStakeDistr {
  PoolA -> PerasVoteStake (1_000_000_000_000 % 1),  -- 1 trillion lovelace
  PoolB -> PerasVoteStake (500_000_000_000 % 1),
  ...
}
```

`perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 % 4)` (i.e. `0.75`).

When PoolA sends a single vote, `validatePerasVote` assigns `vpvVoteStake = 1_000_000_000_000`. `stakeAboveThreshold` then evaluates:

```
1_000_000_000_000 >= 0.75 + 0.02  -- True
```

A single vote from PoolA triggers quorum. `forgePerasCert` is called, producing a `ValidatedPerasCert` that boosts an arbitrary block chosen by PoolA. This certificate propagates via the Peras cert diffusion protocol and is accepted by all honest nodes, corrupting their chain selection with a `PerasWeight` boost on an adversarially chosen block.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L93-98)
```haskell
-- | Total stake needed to forge a Peras certificate.
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-174)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
```

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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasVoteDB/Model.hs (L243-247)
```haskell
  hadQuorum =
    stakeAboveThreshold (params model) existingVotesStake
  -- Did we reach the quorum threshold with this new vote?
  reachedQuorum =
    stakeAboveThreshold (params model) extendedVotesStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L107-113)
```haskell
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```
