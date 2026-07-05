### Title
Peras Quorum Check Compares Unnormalized Absolute Vote Stake Against Relative Threshold - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares a `PerasVoteStake` value — which may carry absolute (unnormalized) ledger stake — directly against a relative quorum threshold, without performing the required normalization by total committee stake. The production code itself documents this as an unresolved correctness gap. This is the direct analog of the BunniPrice bug: a total/absolute value is used where a per-unit/normalized value is required.

### Finding Description

`stakeAboveThreshold` is the sole gate that decides whether a collection of Peras votes has reached quorum and a certificate can be forged:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake     = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
``` [1](#0-0) 

The `PerasQuorumStakeThreshold` is a `Rational` intended to represent a **relative** fraction of total committee stake (e.g. `0.75` for 75%). The production comment immediately above `stakeAboveThreshold` explicitly states:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `PerasVoteStake` type itself carries the same warning:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [3](#0-2) 

`stakeAboveThreshold` is called directly from `votesReachQuorum`, which is the smart constructor for `ValidatedPerasVotesWithQuorum` — the only type that can be passed to `forgePerasCert`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) 

The `vpvVoteStake` field of `ValidatedPerasVote` is populated by `validatePerasVote` (a `BlockSupportsPeras` method). The `implEligiblePartyVoteWeight` function in `WFALS.hs` reveals the normalization asymmetry at the committee layer: **persistent members receive their raw absolute ledger stake as vote weight**, while non-persistent members receive stake normalized by total non-persistent stake:

```haskell
-- Persistent members have their voting power equal to their stake
WFALSPersistentMember _seatIndex (LedgerStake stake) ->
    VoteWeight stake                          -- absolute, NOT normalized

-- Non-persistent members: normalized by total non-persistent stake
WFALSNonPersistentMember _seatIndex (LedgerStake stake) _ numSeats ->
    VoteWeight $ fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
                   * stake / nonPersistentStake   -- normalized
``` [5](#0-4) 

If the absolute ledger stake (in lovelace, e.g. `1_000_000_000_000`) flows into `PerasVoteStake` and is summed in `totalVoteStake`, the comparison `totalVoteStake >= 0.75` is trivially true for any single vote from any voter with positive stake. Quorum is bypassed entirely.

### Impact Explanation

A single unprivileged peer holding any positive stake can submit one Peras vote. If `PerasVoteStake` carries absolute lovelace values, `stakeAboveThreshold` immediately returns `True`, `votesReachQuorum` succeeds, and `forgePerasCert` produces a `ValidatedPerasCert`. This certificate is then accepted by honest nodes via `validatePerasCert`, boosting an arbitrary block with `vpcCertBoost` weight. Because Peras chain selection (`wsvTotalWeight`) adds this boost to the block's weight, the boosted block is preferred in chain selection over heavier honest chains, constituting a **Peras certificate quorum bypass** and a **chain-selection safety failure**. [6](#0-5) 

### Likelihood Explanation

The normalization gap is documented in production code with a `TODO` that has not been resolved. Any implementation of `validatePerasVote` that passes absolute ledger stake directly into `vpvVoteStake` — which is the natural, unguarded path given the `PerasVoteStake` type carries no normalization invariant — triggers the bypass. An unprivileged peer needs only to submit a single valid vote signature; no stake majority, key compromise, or admin access is required.

### Recommendation

`stakeAboveThreshold` must normalize `PerasVoteStake` by the total committee stake before comparing against the relative quorum threshold:

```haskell
stakeAboveThreshold :: PerasParams -> TotalCommitteeStake -> PerasVoteStake -> Bool
stakeAboveThreshold params totalStake voteStake =
  (unPerasVoteStake voteStake / totalStake) >= quorumThreshold + safetyMargin
```

Alternatively, enforce at the type level that `PerasVoteStake` is always a relative value in `[0,1]` by normalizing inside `validatePerasVote` / `implEligiblePartyVoteWeight` before the value is stored, and add a property test asserting `sum (map vpvVoteStake allVoters) == 1`. [7](#0-6) 

### Proof of Concept

1. Construct a `PerasVote` from a pool with absolute ledger stake `s = 1_000_000_000` lovelace.
2. `validatePerasVote` sets `vpvVoteStake = PerasVoteStake (fromIntegral s)` (absolute, not normalized).
3. `votesReachQuorum cfg [vote]` calls `stakeAboveThreshold cfg (PerasVoteStake 1_000_000_000)`.
4. `quorumThreshold = 0.75` (relative). The check `1_000_000_000 >= 0.75 + safetyMargin` is `True`.
5. `forgePerasCert` produces a `ValidatedPerasCert` with `vpcCertBoost` for an arbitrary block.
6. Honest nodes accept the certificate via `validatePerasCert`, boosting the attacker-chosen block in chain selection. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L412-432)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L93-98)
```haskell
-- | Total stake needed to forge a Peras certificate.
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
```
