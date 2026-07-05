### Title
Peras Quorum Check Compares Accumulated Absolute Stake Against a Relative Threshold Without Normalization, Enabling Unauthorized Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares a running total of `PerasVoteStake` values — accumulated vote-by-vote in `updateTargetVoteTally` — directly against `perasQuorumStakeThreshold`, a relative (normalized) `Rational` fraction. The code itself carries a `TODO` acknowledging that no normalization is performed and that the two quantities may be in different units. If the `PerasVoteStakeDistr` supplied at runtime contains absolute ledger-stake values (lovelace), a single vote from any pool with positive stake will satisfy the quorum check, causing the node to forge a Peras certificate for an attacker-chosen block and boost that block's chain weight.

---

### Finding Description

`PerasVoteStake` is a bare `Rational` newtype with no unit enforcement:

```haskell
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
  deriving Semigroup via Sum Rational
  deriving Monoid    via Sum Rational
```

The code comment at the definition site explicitly states the unit ambiguity:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."

`updateTargetVoteTally` accumulates these values unconditionally:

```haskell
| (Nothing, votes') <- swapVote vote ptvtVotes =
    (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
```

The accumulated total is then passed to `stakeAboveThreshold`, which compares it directly against the relative quorum threshold:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake            = unPerasVoteStake voteStake          -- may be absolute lovelace
  quorumThreshold  = unPerasQuorumStakeThreshold ...     -- relative fraction, e.g. 0.75
  safetyMargin     = unPerasQuorumStakeThresholdSafetyMargin ...
```

The `TODO` comment on `stakeAboveThreshold` confirms the defect:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

In production, `PerasVoteStakeDistr` is populated from the ledger's stake distribution and passed in via `getStakeDistrSTM`. Ledger stake is measured in lovelace (absolute integers). The quorum threshold `perasQuorumStakeThreshold` is a relative fraction (e.g., `0.75`). When a vote arrives, `validatePerasVote` looks up the voter's entry in `PerasVoteStakeDistr` and attaches it as `vpvVoteStake`. That absolute value is then summed into `ptvtTotalStake` and compared against `0.75`. Any pool with even 1 lovelace of stake satisfies `1 >= 0.75`, so the very first vote triggers quorum.

---

### Impact Explanation

When `PerasVoteStakeDistr` holds absolute ledger-stake values, a single inbound vote from any pool with positive stake causes `stakeAboveThreshold` to return `True`, triggering `forgePerasCert` and producing a `ValidatedPerasCert` for the block the vote targeted. That certificate is stored in the `PerasVoteDB` / `ChainDB` and its `vpcCertBoost` (`perasWeight`) is added to the chain-selection weight of the boosted block via `weightBoostOfFragment` / `totalWeightOfFragment`. An adversary can therefore:

1. Send one vote for any block of their choice.
2. Cause the local node to forge a Peras certificate for that block.
3. Inflate that block's chain-selection weight by `perasWeight`, potentially making a minority or adversarial chain preferred over the honest chain.

This is a bypass of the Peras quorum requirement (intended to require >¾ of total stake) that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The entry path is the ObjectDiffusion mini-protocol, which is reachable by any unprivileged peer. `processVotes` accepts inbound votes, validates them against the stake distribution, and adds them to the DB. No operator action is required. The only precondition is that the attacker controls a pool ID present in the current `PerasVoteStakeDistr` — i.e., any pool with positive ledger stake. The defect is present in the production code path (`makePerasVotePoolWriterFromChainDB` → `validatePerasVote mkPerasParams sd vote` → `addVote`).

---

### Recommendation

`stakeAboveThreshold` must normalize `ptvtTotalStake` before comparing it against the relative quorum threshold. The normalization requires dividing the accumulated absolute stake by the total stake of the voting committee. Concretely:

- Either pass the total committee stake into `stakeAboveThreshold` and compute `normalizedStake = accumulatedAbsoluteStake / totalCommitteeStake` before the comparison, or
- Store only pre-normalized (relative) values in `PerasVoteStakeDistr` by dividing each voter's absolute ledger stake by the total committee stake at the time the distribution is built.

The `TODO` comment at lines 155–161 of `SupportsPeras.hs` already identifies the correct fix direction. It must be resolved before Peras is enabled on any live network.

---

### Proof of Concept

Assume a pool `P` with 1,000,000 lovelace of ledger stake. The `PerasVoteStakeDistr` entry for `P` is `PerasVoteStake (1000000 % 1)`. Default `mkPerasParams` sets `perasQuorumStakeThreshold = 0.75` and `perasQuorumStakeThresholdSafetyMargin = 0`.

1. Peer sends one `PerasVote` for block `B` in round `R`, signed by pool `P`.
2. `validatePerasVote mkPerasParams sd vote` succeeds; `vpvVoteStake = PerasVoteStake (1000000 % 1)`.
3. `updateTargetVoteTally` sets `ptvtTotalStake = 1000000 % 1`.
4. `stakeAboveThreshold` evaluates `1000000 >= 0.75` → `True`.
5. `forgePerasCert` is called; a `ValidatedPerasCert` for block `B` is stored.
6. `weightBoostOfFragment` adds `perasWeight` to block `B`'s chain-selection score.
7. The node may now prefer a chain containing `B` over the honest chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-161)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L453-459)
```haskell
    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
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
