### Title
Peras Quorum Check Compares Absolute and Relative Stake Without Unit Normalization, Enabling Certificate Forgery Bypass - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares accumulated `PerasVoteStake` (a `Rational`) directly against `perasQuorumStakeThreshold` (also a `Rational`, set to `3/4`) without enforcing that both values are expressed in the same unit. The code itself carries a `TODO` comment acknowledging this assumption is unverified. If `PerasVoteStakeDistr` is populated with absolute ledger stake values (e.g., lovelace), any single vote with positive stake would immediately satisfy the quorum threshold, allowing unauthorized Peras certificate forging and bypassing the quorum requirement entirely.

### Finding Description

In `stakeAboveThreshold`:

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
```

`perasQuorumStakeThreshold` is a relative value (`3/4 = 0.75`) set in `mkPerasParams`. `PerasVoteStake` is a bare `Rational` with no type-level distinction between absolute and relative units. The comment at lines 136–143 explicitly states there is "no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake."

The call chain is:

1. A peer sends `PerasVote` messages via the Peras vote diffusion miniprotocol.
2. `makePerasVotePoolWriterFromChainDB` (in `PerasVote.hs`, line 141) calls `validatePerasVote mkPerasParams sd vote`, where `sd` is the `PerasVoteStakeDistr` sourced from the ledger.
3. `validatePerasVote` (line 363–371) looks up the voter's stake from `PerasVoteStakeDistr` and stores it verbatim as `vpvVoteStake` — no normalization is performed.
4. As votes accumulate, `votesReachQuorum` (line 269–270) calls `stakeAboveThreshold cfg totalVoteStake`.
5. If `PerasVoteStakeDistr` is populated with absolute lovelace values (e.g., `1_000_000_000` for 1 ADA), then `unPerasVoteStake voteStake = 1000000000`, which is trivially `>= 0.75`, so `stakeAboveThreshold` returns `True` for any single vote.

The production wiring in `NodeToNode.hs` (line 406) currently passes `pure (PerasVoteStakeDistr mempty)` — an empty distribution — as a placeholder, causing all votes to fail validation. The TODO comment at line 402–405 explicitly states this will be replaced with actual ledger stake data. When that plumbing is connected without adding normalization, the unit mismatch becomes immediately exploitable.

### Impact Explanation

When `PerasVoteStakeDistr` is populated with absolute ledger stake (the natural representation from the Cardano ledger), a single vote from any voter with any positive stake satisfies `stakeAboveThreshold`, because any positive integer as a `Rational` exceeds `0.75`. This causes `votesReachQuorum` to return `Just` and `forgePerasCert` to be called, producing a `ValidatedPerasCert` with `vpcCertBoost = perasWeight params` (15 chain-weight units). An adversary who can send a single valid `PerasVote` message (i.e., any registered stake pool operator) can forge a certificate for any block of their choosing, boosting its chain weight by 15 and causing honest nodes to prefer that block over the canonical chain. This is a bypass of the Peras quorum/certificate check.

### Likelihood Explanation

The vulnerability is latent but has a concrete, documented activation path: the `TODO` comment in `NodeToNode.hs` (line 402–405) explicitly describes the next implementation step as connecting real ledger stake data. The `stakeAboveThreshold` function is already wired into the production vote aggregation path (`updateCandidateVoteState`, `updateLoserVoteState`, `votesReachQuorum`). Any stake pool operator can send `PerasVote` messages via the Peras vote diffusion miniprotocol, which is the externally reachable entry point. No key compromise or admin access is required beyond having a registered stake pool key.

### Recommendation

Before connecting real ledger stake data to `PerasVoteStakeDistr`, normalize each voter's absolute stake to a relative fraction of total committee stake before storing it in `PerasVoteStakeDistr`. Alternatively, change `stakeAboveThreshold` to accept the total committee stake and perform normalization internally. The type `PerasVoteStake` should be given a phantom unit tag (e.g., `Absolute` vs `Relative`) to make unit mismatches a compile-time error. The `TODO` comment at lines 155–161 should be resolved before the stake distribution plumbing is activated.

### Proof of Concept

Given `mkPerasParams` with `perasQuorumStakeThreshold = 3/4`:

```haskell
-- Suppose PerasVoteStakeDistr is populated with absolute lovelace:
-- voter A has 1,000,000 lovelace (0.001 ADA)
let stakeDistr = PerasVoteStakeDistr $ Map.singleton voterA (PerasVoteStake 1000000)

-- validatePerasVote stores this verbatim:
-- vpvVoteStake = PerasVoteStake 1000000

-- stakeAboveThreshold check:
-- stake = 1000000
-- quorumThreshold = 3/4 = 0.75
-- safetyMargin = 2/100 = 0.02
-- 1000000 >= 0.75 + 0.02  =>  True  (quorum "reached" with one vote)
```

A single `PerasVote` message from any voter with positive absolute stake causes `votesReachQuorum` to return `Just`, triggering `forgePerasCert` and producing a `ValidatedPerasCert` that boosts the adversary's chosen block by `perasWeight = 15` chain-weight units. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
