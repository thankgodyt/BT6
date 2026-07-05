### Title
Non-Persistent Peras Vote Weight Normalized by Local Non-Persistent Stake Instead of Global Total Stake, Causing Incorrect Quorum Determination — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs`)

---

### Summary

`implEligiblePartyVoteWeight` in `WFALS.hs` computes vote weights for the two committee member types using **different normalization bases**: persistent members receive their raw absolute ledger stake, while non-persistent members receive their stake normalized by `totalNonPersistentStake` — a local, partial value covering only the non-persistent subset of voters. The quorum threshold in `stakeAboveThreshold` is expressed as a fraction of **total** stake (global). This unit mismatch inflates non-persistent vote weights by a factor of `totalStake / totalNonPersistentStake`, allowing a coalition of non-persistent voters whose combined stake is below the quorum threshold to forge a Peras certificate.

---

### Finding Description

In `implEligiblePartyVoteWeight`:

```haskell
-- Persistent members: absolute ledger stake
WFALSPersistentMember _seatIndex (LedgerStake stake) ->
  VoteWeight stake

-- Non-persistent members: stake / totalNonPersistentStake  (NOT / totalStake)
WFALSNonPersistentMember _seatIndex (LedgerStake stake) _vrfOutput numSeats ->
  VoteWeight $
    fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
      * stake
      / nonPersistentStake          -- ← local partial denominator
 where
  TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
    totalNonPersistentStake committee
``` [1](#0-0) 

`totalNonPersistentStake` is the cumulative stake of only the non-persistent voters, computed in `weightedFaitAccompliSplitSeats` as the residual after persistent seats are assigned. It is strictly less than total stake whenever any persistent seats exist. [2](#0-1) 

The quorum check in `stakeAboveThreshold` compares the accumulated `PerasVoteStake` directly against `perasQuorumStakeThreshold`, which is a fraction of **total** stake. The code itself carries an explicit acknowledgement of the unit-mismatch hazard:

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
``` [3](#0-2) 

The `VoteWeight` values produced by `eligiblePartyVoteWeight` are the source of the `PerasVoteStake` entries that flow into `votesReachQuorum` → `stakeAboveThreshold`. The quorum check in `votesReachQuorum` sums `vpvVoteStake` across all votes and calls `stakeAboveThreshold`: [4](#0-3) 

The structural parallel to the external report is exact:

| External report | Ouroboros Consensus |
|---|---|
| `totalStaked` (local per-manager) | `totalNonPersistentStake` (local non-persistent subset) |
| `totalRewards` (global from ValidatorManager) | `perasQuorumStakeThreshold` (global fraction of total stake) |
| Incorrect `exchangeRate` | Incorrect quorum determination |

---

### Impact Explanation

Non-persistent voters whose combined stake is below the quorum threshold of **total** stake can forge a valid Peras certificate if their combined fraction of **non-persistent** stake exceeds the threshold.

Concrete example:
- Total stake = 100; persistent stake = 70; non-persistent stake = 30
- Quorum threshold = 0.75 (75 % of total stake)
- Three non-persistent voters each holding 10 stake

Incorrect calculation (current code):
```
VoteWeight per voter = 1 × 10 / 30 = 0.333
Combined             = 3 × 0.333  = 1.0  ≥ 0.75  → certificate forged
```

Correct calculation (should use total stake):
```
VoteWeight per voter = 1 × 10 / 100 = 0.10
Combined             = 3 × 0.10     = 0.30 < 0.75 → certificate NOT forged
```

An accepted Peras certificate boosts the weight of the certified block in chain selection. Unauthorized certificate acceptance therefore constitutes a bypass of Peras vote/certificate authorization, enabling an adversary to influence chain selection without holding the required stake.

---

### Likelihood Explanation

**High.** The condition is triggered whenever non-persistent voters collectively hold a non-trivial fraction of non-persistent stake while their fraction of total stake is below the quorum threshold — a routine configuration whenever persistent voters hold a large share of total stake. No key compromise, operator error, or stake majority is required. Any unprivileged peer that is a non-persistent committee member can participate in this coalition by sending crafted votes through the standard Peras vote diffusion path.

---

### Recommendation

In `implEligiblePartyVoteWeight`, normalize non-persistent vote weights by the **total** stake of all voters (persistent + non-persistent), not by `totalNonPersistentStake` alone:

```haskell
-- Correct denominator: totalPersistentStake + totalNonPersistentStake
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / (persistentStake + nonPersistentStake)
```

Alternatively, normalize persistent vote weights by total stake as well, so that all `VoteWeight` values are fractions of total stake before they are compared against the quorum threshold. The `stakeAboveThreshold` TODO comment should be resolved by enforcing the invariant at the type level or at the construction site of `PerasVoteStakeDistr`.

---

### Proof of Concept

1. Deploy a private testnet with Peras enabled; configure a committee with total stake 100, persistent stake 70 (one pool), non-persistent stake 30 (three pools of 10 each), and quorum threshold 0.75.
2. The three non-persistent pools collectively hold 30 % of total stake — below the 75 % quorum.
3. Each non-persistent pool calls `implCheckShouldVote`; each receives `VoteWeight = 1 × 10/30 = 0.333`.
4. All three cast votes for the same block in the same round; the node accumulates `PerasVoteStake = 1.0`.
5. `stakeAboveThreshold` evaluates `1.0 ≥ 0.75` → `True`; `votesReachQuorum` returns `Just`; `forgePerasCert` is called.
6. The certificate is accepted and the block receives a Peras boost, influencing chain selection — despite the coalition holding only 30 % of total stake. [5](#0-4) [3](#0-2) [6](#0-5)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs (L128-133)
```haskell
        Right
          ( PersistentCommitteeSize numPersistentVoters
          , NonPersistentCommitteeSize numNonPersistentVoters
          , TotalPersistentStake (Cumulative (LedgerStake persistentStake))
          , TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake))
          )
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
