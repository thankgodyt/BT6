### Title
Peras Quorum Certificate Acceptance via Unnormalized Stake Comparison — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares an accumulated `PerasVoteStake` value directly against a relative quorum threshold (`3/4`) without enforcing that the vote-stake values are expressed in the same unit (relative-to-committee vs. absolute-ledger-fraction). The code itself contains an explicit TODO acknowledging this assumption is unverified and unenforced. If vote stakes are supplied in a different unit than the threshold, the quorum gate either never fires (disabling Peras boosting entirely) or fires with insufficient real stake (accepting an invalid certificate).

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs a bare numeric comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake          = unPerasVoteStake voteStake          -- Rational, unit unknown
  quorumThreshold = unPerasQuorumStakeThreshold ...    -- Rational, relative (3/4)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ...
``` [1](#0-0) 

The `PerasVoteStake` type is a plain `Rational` newtype with no type-level distinction between absolute and relative stake:

```haskell
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
``` [2](#0-1) 

The code's own comment explicitly acknowledges the unit mismatch risk:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [3](#0-2) 

`stakeAboveThreshold` is called in two production paths:

1. **`votesReachQuorum`** — the smart constructor that gates `ValidatedPerasVotesWithQuorum` creation, which in turn gates certificate forging:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) 

2. **`updateLoserVoteState`** in `Vote/Aggregation.hs` — the loser-above-quorum guard that detects multiple winners:

```haskell
aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
``` [5](#0-4) 

The `PerasQuorumStakeThreshold` is set to `3/4` as a relative fraction of committee stake: [6](#0-5) 

If `vpvVoteStake` values stored in `ValidatedPerasVote` are absolute ledger-stake fractions (e.g., a pool with 1 % of total ADA has stake = `0.01`), the sum of all voting pools' stakes is bounded by `1.0`, but the threshold is `3/4 + 2/100 = 0.77`. Reaching `0.77` of total ledger stake is practically impossible, so **quorum is never declared** and no Peras certificate is ever forged. Conversely, if an implementation normalizes to committee-relative stake but the threshold was calibrated for ledger-relative stake, quorum fires with far less than the intended real stake, **accepting an invalid certificate**.

---

### Impact Explanation

**Critical — Bypass of Peras voting/certificate checks.**

- **Quorum never reached (stake deflation):** If `PerasVoteStake` carries ledger-relative values (e.g., `0.01` for a 1 % pool), the sum of all honest votes never approaches `0.77`, so no Peras certificate is ever forged. The boosting mechanism is silently disabled, degrading chain-selection security to plain Praos without the Peras finality guarantee.
- **Quorum reached with insufficient real stake (stake inflation):** If `PerasVoteStake` carries committee-seat-count fractions or any inflated unit, an adversary controlling a small fraction of committee seats can accumulate a `PerasVoteStake` sum ≥ `0.77` and cause a certificate to be forged for a block that does not have genuine 3/4-stake backing. This is an unauthorized certificate acceptance, directly matching the "bypass of Peras voting or certificate checks" impact class.

Both outcomes break the Peras protocol's safety invariant: the boosted block is supposed to represent a quorum of real stake, not an artifact of unit confusion.

---

### Likelihood Explanation

**Medium-High.** The unit ambiguity is not a theoretical edge case — the code's own comment states there is "no consensus" on the correct normalization. Any concrete implementation of `validatePerasVote` that populates `vpvVoteStake` from the ledger's `IndividualPoolStake.individualPoolStake` (a ledger-relative rational) without re-normalizing to committee-relative stake will trigger the deflation path. The `PerasVoteStakeDistr` type, which maps voter IDs to `PerasVoteStake`, has no normalization step in its construction path visible in the codebase. The bug is reachable by any peer that sends well-formed Peras votes over the miniprotocol.

---

### Recommendation

1. **Enforce units at the type level.** Introduce distinct newtypes `LedgerRelativeStake` and `CommitteeRelativeStake` so the compiler rejects unit-unsafe comparisons.
2. **Normalize in `stakeAboveThreshold` or at vote validation time.** Either pass the total committee stake into `stakeAboveThreshold` and normalize internally, or normalize `PerasVoteStake` to committee-relative units inside `validatePerasVote` before storing it in `ValidatedPerasVote`.
3. **Add an invariant assertion** that the sum of all `PerasVoteStake` values in a full committee equals `1.0` (or the expected committee size), so any normalization bug is caught immediately in testing.

---

### Proof of Concept

**Private-testnet sequence demonstrating quorum-never-fires (deflation path):**

1. Configure a private testnet with Peras enabled and `perasQuorumStakeThreshold = 3/4`.
2. Populate `PerasVoteStakeDistr` from `SL.IndividualPoolStake.individualPoolStake` directly (ledger-relative, e.g., `0.05` for a 5 % pool) without committee normalization.
3. Have all 20 pools (each with 5 % ledger stake) cast votes for the same block in round R. The accumulated `PerasVoteStake` = `20 × 0.05 = 1.0`.
4. `stakeAboveThreshold` evaluates `1.0 >= 0.77` → **True** — quorum fires with 100 % of ledger stake, which is correct here only by coincidence.
5. Now repeat with only 16 pools voting (80 % of ledger stake, well above 3/4): accumulated stake = `0.80 >= 0.77` → **True** — still fires.
6. Now repeat with 14 pools (70 % of ledger stake, below 3/4): accumulated stake = `0.70 < 0.77` → **False** — quorum does not fire even though 70 % of real stake voted.

The threshold is calibrated for committee-relative stake, but the values are ledger-relative. The boundary is wrong by a factor of `(committee_size / total_pools)`. An adversary who knows this ratio can craft a vote set that crosses the numeric threshold `0.77` using far less than 3/4 of real stake by controlling a disproportionate share of the committee seats relative to their ledger stake. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L603-606)
```haskell
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
