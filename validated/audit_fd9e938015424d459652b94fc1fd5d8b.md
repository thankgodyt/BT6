### Title
Peras Quorum Check Compares Unnormalized Absolute Vote Stake Against a Relative Threshold, Bypassing Certificate Authorization - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares a `PerasVoteStake` value directly against the `perasQuorumStakeThreshold` without any normalization. The code itself acknowledges in a TODO comment that `PerasVoteStake` may carry **absolute** ledger stake (lovelace), while the quorum threshold is a **relative** fraction (e.g., `0.75`). Because the two quantities are in different units, the comparison is semantically invalid. Depending on the actual stake values, quorum is either trivially satisfied by a single vote from any persistent committee member (absolute stake >> relative threshold), or it can never be satisfied. The former case allows an unprivileged peer who is a persistent committee member to forge a Peras certificate unilaterally, bypassing the quorum requirement entirely.

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

`PerasVoteStake` is a bare `Rational` with no enforced unit:

```haskell
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
``` [2](#0-1) 

The quorum threshold (`perasQuorumStakeThreshold`) is a `Rational` intended to be a relative value (e.g., `0.75` meaning 75% of total committee stake):

```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
``` [3](#0-2) 

The `PerasVoteStake` values stored in `PerasVoteStakeDistr` originate from `implEligiblePartyVoteWeight` in `WFALS.hs`. For **persistent** committee members, the vote weight is set to the raw absolute ledger stake:

```haskell
WFALSPersistentMember
  _seatIndex
  (LedgerStake stake) ->
    VoteWeight stake
``` [4](#0-3) 

For **non-persistent** members, the weight is normalized by total non-persistent stake:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [5](#0-4) 

These heterogeneous values (absolute for persistent, relative for non-persistent) are stored in `PerasVoteStakeDistr` and then summed in `votesReachQuorum`:

```haskell
totalVoteStake =
  mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake =
  stakeAboveThreshold cfg totalVoteStake
``` [6](#0-5) 

No normalization step exists between `lookupPerasVoteStake` and `stakeAboveThreshold`. The `validatePerasVote` implementation simply passes the raw stake through:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [7](#0-6) 

---

### Impact Explanation

When persistent committee members' absolute ledger stake (e.g., `1_000_000_000` lovelace) is compared against a relative quorum threshold (e.g., `0.75`), the condition `1_000_000_000 >= 0.75 + safetyMargin` is trivially `True`. A single vote from any persistent committee member with non-trivial stake immediately satisfies quorum, regardless of how many other committee members have voted. This is a **bypass of the Peras certificate quorum check**: an attacker who is a persistent committee member can forge a `ValidatedPerasCert` for any block of their choosing with a single vote. In Peras, certificates boost blocks and directly influence chain selection weight (`PerasWeight`), so a forged certificate can cause honest nodes to prefer an adversary-chosen block, constituting a chain-selection manipulation.

---

### Likelihood Explanation

Persistent committee membership is determined by the stake distribution — the highest-stake pools are selected as persistent members. Any pool operator with sufficient stake to be a persistent committee member (a relatively low bar on a real network) can exploit this by sending a single crafted vote for any block. The vote is received via the Peras vote mini-protocol, which is an externally reachable network path. No key compromise or operator privilege beyond normal pool operation is required.

---

### Recommendation

Before calling `stakeAboveThreshold`, normalize the accumulated `PerasVoteStake` by dividing by the total committee stake (or the total stake of all voters who cast votes). Alternatively, change `stakeAboveThreshold` to accept the `PerasVoteStakeDistr` and compute the normalization internally. The fix must ensure that both the accumulated vote stake and the quorum threshold are expressed as fractions of the same total, as the TODO comment itself prescribes:

```haskell
-- Either normalize before calling:
let totalStake = sum (Map.elems (unPerasVoteStakeDistr distr))
    normalizedVoteStake = totalVoteStake / totalStake
in stakeAboveThreshold cfg normalizedVoteStake

-- Or change the signature to:
stakeAboveThreshold :: PerasParams -> PerasVoteStakeDistr -> PerasVoteStake -> Bool
```

---

### Proof of Concept

Given:
- `perasQuorumStakeThreshold = 0.75` (relative, 75% of total committee stake)
- Persistent committee member P has absolute ledger stake = `2_000_000_000` lovelace
- `PerasVoteStakeDistr` maps P's voter ID to `PerasVoteStake (2_000_000_000 % 1)`

Attack sequence:
1. Attacker (pool operator P) crafts a `PerasVote` for an adversarial block B at round R.
2. The vote is sent to an honest node via the Peras vote mini-protocol.
3. `validatePerasVote` looks up P's stake: `PerasVoteStake (2_000_000_000 % 1)`.
4. `votesReachQuorum` computes `totalVoteStake = 2_000_000_000`.
5. `stakeAboveThreshold` evaluates `2_000_000_000 >= 0.75 + safetyMargin` → `True`.
6. `forgePerasCert` is called, producing a `ValidatedPerasCert` boosting block B.
7. The certificate is stored and used to boost B's chain weight, causing honest nodes to prefer B over the canonical chain.

This can be repeated each round to persistently steer chain selection toward adversary-chosen blocks.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L144-151)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L94-98)
```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L413-417)
```haskell
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-432)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
```
