### Title
Peras Quorum Calculation Missing Stake Normalization Enables Trivial or Unreachable Certificate Quorum — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function, which is the sole gate for Peras certificate forging, compares the raw sum of `PerasVoteStake` values against `perasQuorumStakeThreshold` without normalizing the vote stakes against the total stake distribution. The code itself carries an explicit TODO acknowledging this unit mismatch. When the production stake-distribution plumbing is wired in (replacing the current empty-map placeholder), the comparison will be between incommensurable quantities — absolute ledger stake on one side and a relative fraction on the other — causing the quorum check to be either trivially satisfied by any single voter (unauthorized certificate forging) or permanently unsatisfiable (Peras boosting permanently broken), depending on how the distribution is populated.

---

### Finding Description

**Step 1 — The quorum gate.**

`stakeAboveThreshold` is the single function that decides whether a Peras certificate may be forged:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake     = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (...)
``` [1](#0-0) 

The threshold (`perasQuorumStakeThreshold`) is a `Rational` intended to represent a *relative* fraction of total committee stake (e.g. `3 % 4` for 75 %).

**Step 2 — The acknowledged unit mismatch.**

The code itself documents the problem:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

**Step 3 — Vote stake is assigned without normalization.**

`validatePerasVote` (the degenerate production instance) simply looks up the voter's entry in `PerasVoteStakeDistr` and stores it verbatim as `vpvVoteStake`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

`PerasVoteStakeDistr` is a plain `Map PerasVoterId PerasVoteStake`; there is no type-level or runtime guarantee that the values it contains are normalized fractions rather than absolute ledger quantities. [4](#0-3) 

**Step 4 — The quorum check is called on the raw sum.**

`votesReachQuorum` sums `vpvVoteStake` across all votes and passes the raw sum directly to `stakeAboveThreshold`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [5](#0-4) 

This is called from `updateCandidateVoteState` and `updateLoserVoteState` in the vote aggregation engine, which is the production path for every inbound Peras vote. [6](#0-5) 

**Step 5 — Production entry point.**

The node-to-node handler wires the vote diffusion inbound path to `makePerasVotePoolWriterFromChainDB`, which calls `validatePerasVote` and then `implAddVote` → `updatePerasRoundVoteStates` → `stakeAboveThreshold`. Currently the stake distribution is hard-coded to `mempty` (all votes rejected), but the TODO comment confirms this is a placeholder:

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
--
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [7](#0-6) 

---

### Impact Explanation

Two failure modes arise from the unit mismatch, depending on how `PerasVoteStakeDistr` is populated when the plumbing is completed:

**Mode A — Trivial quorum (critical).**  
If the distribution is populated with absolute ledger stakes (the natural reading from the Cardano ledger, e.g. values in Lovelace), then a single voter with even 1 Lovelace contributes `PerasVoteStake = 1 % 1`. The threshold is `3 % 4`. Since `1 >= 3/4` is `True`, *any single vote* causes `stakeAboveThreshold` to return `True`, and a certificate is forged immediately. An unprivileged peer can send a single crafted vote and cause the node to forge and accept a Peras certificate for an arbitrary block, directly manipulating chain selection via the boost weight.

**Mode B — Unreachable quorum (high, direct analog to the external report).**  
If the distribution is populated with per-voter fractions of total stake but includes retired or inactive pools (whose votes will never arrive), the sum of *active* vote stakes is permanently below the threshold — exactly the burned-token scenario from the external report. Peras boosting is permanently broken for the node, weakening its chain-selection security guarantees.

Both modes are reachable via the Peras vote diffusion mini-protocol from any unprivileged peer once the stake-distribution plumbing is in place.

---

### Likelihood Explanation

The production code currently uses `PerasVoteStakeDistr mempty`, so neither failure mode is exploitable today. However:

1. The TODO comment in `NodeToNode.hs` explicitly marks this as a known placeholder to be replaced.
2. The TODO comment in `stakeAboveThreshold` explicitly identifies the normalization requirement as unresolved.
3. The WFALS committee implementation (`implEligiblePartyVoteWeight`) shows that persistent members receive *absolute* ledger stake as their vote weight, confirming that absolute values are the natural output of the committee selection layer. [8](#0-7) 

When the plumbing is wired, Mode A (trivial quorum) is the most likely outcome unless normalization is explicitly added.

---

### Recommendation

1. **Normalize at validation time.** `validatePerasVote` should divide the voter's absolute ledger stake by the total stake of the distribution before storing it as `vpvVoteStake`. This mirrors the non-persistent member normalization already present in `implEligiblePartyVoteWeight`.
2. **Enforce units at the type level.** Introduce distinct newtypes for absolute and relative stake (e.g. `AbsoluteStake` vs `RelativeStake`) so that `stakeAboveThreshold` can only accept a normalized value, making the unit mismatch a compile-time error.
3. **Remove the TODO and fix before wiring the plumbing.** The normalization must be resolved before `PerasVoteStakeDistr mempty` is replaced with a real distribution, or the certificate forging gate will be broken in one of the two directions described above.

---

### Proof of Concept

Assume the stake distribution is populated with absolute Lovelace values (the natural ledger output):

```
PerasVoteStakeDistr = { voterA → PerasVoteStake (1_000_000_000_000 % 1) }
perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 % 4)   -- 75 %
perasQuorumStakeThresholdSafetyMargin = 0
```

A peer sends a single vote from `voterA`. `validatePerasVote` looks up `voterA` and assigns `vpvVoteStake = 1_000_000_000_000 % 1`. `votesReachQuorum` calls `stakeAboveThreshold`:

```
stake = 1_000_000_000_000 % 1
quorumThreshold + safetyMargin = 3 % 4
1_000_000_000_000 % 1 >= 3 % 4  →  True
```

`votesReachQuorum` returns `Just`, `forgePerasCert` is called, and a `ValidatedPerasCert` is produced for the block the attacker chose — with a full `perasWeight` boost — from a single vote representing an arbitrarily small fraction of actual stake.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L175-179)
```haskell
newtype PerasVoteStakeDistr = PerasVoteStakeDistr
  { unPerasVoteStakeDistr :: Map PerasVoterId PerasVoteStake
  }
  deriving newtype NoThunks
  deriving stock (Show, Eq, Generic)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L400-406)
```haskell
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L413-417)
```haskell
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
```
