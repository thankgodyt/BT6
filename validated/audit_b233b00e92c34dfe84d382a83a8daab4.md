### Title
Peras Quorum Check Compares Incompatible Units: Absolute `PerasVoteStake` vs. Relative `perasQuorumStakeThreshold` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in `SupportsPeras.hs` compares the sum of individual `PerasVoteStake` values (which are populated from the raw ledger stake distribution and may be absolute) directly against `perasQuorumStakeThreshold` (which is a relative/normalized value, e.g., `3/4`). No normalization step is applied to the individual vote stakes before the comparison. This is the direct analog of H-06: individual vote weights and the aggregate quorum threshold are computed in different units, making the quorum check systematically incorrect.

---

### Finding Description

In `stakeAboveThreshold`, the total accumulated vote stake is compared against the quorum threshold without any normalization:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin = ...
```

The code itself documents the problem in the comment immediately above `PerasVoteStake`:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."

And in the `stakeAboveThreshold` TODO:

> "this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … Under the current implementation of 'PerasParams', this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

Individual `PerasVoteStake` values are assigned during vote validation via `validatePerasVote`, which simply performs a lookup in `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The `PerasVoteStakeDistr` is populated from the raw ledger stake distribution (absolute lovelace or un-normalized fractions), while `perasQuorumStakeThreshold` is set to a relative value (`3/4` in `mkPerasParams`). The sum of individual vote stakes is then compared against this relative threshold in `votesReachQuorum`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
```

This is structurally identical to H-06: individual contributions are processed with one accounting convention (absolute), while the aggregate threshold uses a different convention (relative), with no reconciliation step.

Additionally, in `WFALS.hs`, `implEligiblePartyVoteWeight` compounds the problem by computing vote weights in two different units depending on committee membership type:
- **Persistent members**: `VoteWeight stake` — raw absolute ledger stake
- **Non-persistent members**: `VoteWeight $ numSeats * stake / nonPersistentStake` — normalized by total non-persistent stake only

These heterogeneous weights are then summed and compared against a single relative quorum threshold, producing a mixed-unit aggregate that is meaningless.

---

### Impact Explanation

**Direction 1 — Quorum never reachable (chain selection failure):** If `PerasVoteStake` values are absolute ledger fractions (e.g., a voter with 10% of total stake contributes `0.10`), the sum of all honest votes across the entire committee is at most `1.0`. With a quorum threshold of `3/4 + 2/100 = 0.77`, quorum is reachable in principle — but only if the stake distribution is already normalized to sum to 1. If the distribution is not normalized (e.g., values are in lovelace), the sum of votes will be astronomically larger than `0.77`, causing quorum to be trivially reached by a single voter.

**Direction 2 — Quorum trivially bypassed (certificate forgery):** If absolute stake values are large (e.g., in lovelace units where a single voter holds `1_000_000_000` lovelace), a single vote immediately satisfies `stake >= 0.77`, allowing any single eligible voter to unilaterally forge a Peras certificate. This bypasses the quorum requirement entirely, enabling unauthorized chain boosting and breaking the safety guarantee that a certificate requires a supermajority of stake.

Both outcomes break the Peras protocol's core security invariant: that a certificate can only be forged when a supermajority of honest stake has voted for the same block.

---

### Likelihood Explanation

The entry path is fully reachable by any unprivileged peer: Peras votes arrive over the network, are validated via `processVotes` → `validatePerasVote`, and are fed into `updatePerasRoundVoteStates` → `votesReachQuorum` → `stakeAboveThreshold`. No special privileges are required. The mismatch is triggered automatically whenever votes are processed. The severity depends on how `PerasVoteStakeDistr` is populated in practice, but the code provides no guarantee of normalization, and the explicit TODO confirms the normalization is missing.

---

### Recommendation

`stakeAboveThreshold` must normalize the accumulated `PerasVoteStake` by the total committee stake before comparing against the relative `perasQuorumStakeThreshold`. The function signature should be changed to accept the total stake of the voting committee:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> PerasVoteStake -> Bool
stakeAboveThreshold params totalCommitteeStake voteStake =
  normalizedStake >= quorumThreshold + safetyMargin
 where
  normalizedStake = unPerasVoteStake voteStake / unPerasVoteStake totalCommitteeStake
  ...
```

Alternatively, `PerasVoteStakeDistr` should be populated with pre-normalized relative values (fractions of total committee stake), and this invariant should be enforced at the point of construction. The `WFALS.implEligiblePartyVoteWeight` function must also ensure that persistent and non-persistent vote weights are expressed in the same normalized unit before they are summed.

---

### Proof of Concept

Consider a Peras voting round with two voters:
- Voter A: absolute ledger stake = `0.6` (60% of total)
- Voter B: absolute ledger stake = `0.5` (50% of total)
- `perasQuorumStakeThreshold = 3/4`, `perasQuorumStakeThresholdSafetyMargin = 2/100`

Both voters vote for the same block. `totalVoteStake = 0.6 + 0.5 = 1.1`. Since `1.1 >= 0.77`, quorum is declared reached. However, the actual combined relative stake is `0.6 + 0.5 = 1.1 > 1.0`, which is impossible — the values are not normalized. In a correct implementation, the normalized stakes would be `0.6/1.1 ≈ 0.545` and `0.5/1.1 ≈ 0.455`, summing to `1.0`, which is above the threshold. But if the distribution is populated with lovelace values (e.g., `600_000_000` and `500_000_000`), a single vote from Voter A trivially satisfies `600_000_000 >= 0.77`, forging a certificate with a single voter's signature — a complete bypass of the quorum requirement. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L408-432)
```haskell
implEligiblePartyVoteWeight ::
  VotingCommittee crypto WFALS ->
  EligibilityWitness crypto WFALS ->
  VoteWeight
implEligiblePartyVoteWeight committee = \case
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
  -- Non-persistent members have their voting power proportional to their
  -- number of seats granted by local sortition and their stake (normalized
  -- by the total non-persistent stake)
  WFALSNonPersistentMember
    _seatIndex
    (LedgerStake stake)
    _vrfOutput
    numSeats ->
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
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
