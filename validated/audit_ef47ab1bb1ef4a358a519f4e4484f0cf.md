### Title
Unnormalized `PerasVoteStake` Bypasses Quorum Check in `stakeAboveThreshold`, Enabling Single-Vote Certificate Forgery — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value directly against a relative quorum threshold (`3/4 + 2/100 = 0.77`) without enforcing that the stake is normalized. The function's own TODO comment acknowledges this assumption is not guaranteed. If the `PerasVoteStakeDistr` supplied to `validatePerasVote` contains absolute ledger-stake values (lovelace amounts), any single vote from a voter with absolute stake > 0.77 trivially passes the quorum check, allowing a certificate to be forged from a single vote and a boosted block to be injected into chain selection.

---

### Finding Description

`stakeAboveThreshold` is the sole gate that decides whether accumulated vote stake reaches quorum:

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

The default `mkPerasParams` sets `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`, giving a combined threshold of `0.77`. [2](#0-1) 

`validatePerasVote` (the default instance) assigns the stake to a vote by a plain map lookup from `PerasVoteStakeDistr` — no normalization, no zero-check, no unit enforcement:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

The production vote-ingestion path in `makePerasVotePoolWriterFromVoteDB` calls `validatePerasVote mkPerasParams sd vote` where `sd` is an STM-supplied `PerasVoteStakeDistr`. The comment there explicitly notes that the stake distribution is read directly from the ledger and that committee-selection weighting is not yet applied:

```haskell
-- TODO: in the future we won't need just the stake distribution for
-- validating votes, but also the whole committee selection context
-- (containing vote weights of committee members = voters)
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

The validated vote (carrying whatever `PerasVoteStake` was in the distribution) flows into `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold`. If the distribution holds absolute lovelace values, a voter with even 1 lovelace of stake produces `PerasVoteStake = 1`, and `1 >= 0.77` is `True`, so quorum is declared reached after a single vote. [5](#0-4) 

The `votesReachQuorum` guard only rejects the empty-list case; it does not reject a single vote whose stake is in wrong units:

```haskell
[] -> Nothing   -- "can't vacuously reach a quorum, even if the quorum threshold is 0"
``` [6](#0-5) 

---

### Impact Explanation

A forged `ValidatedPerasCert` is accepted by the `PerasVoteDB` and forwarded to the `ChainDB`. The certificate carries `vpcCertBoost = perasWeight = 15`, which is added to the chain weight of the boosted block. Honest nodes performing chain selection will prefer the adversarially boosted chain over the canonical chain, constituting a **chain-selection manipulation** that lets an unprivileged peer make honest nodes adopt a non-canonical chain beyond the intended security assumptions of the Peras protocol. [7](#0-6) 

---

### Likelihood Explanation

The entry point is the Peras vote object-diffusion mini-protocol, reachable by any unprivileged peer. The attacker only needs to be a registered stake pool (present in the `PerasVoteStakeDistr`) with any positive stake. The condition triggers whenever the `PerasVoteStakeDistr` is populated with absolute ledger-stake values rather than normalized relative values — a scenario the codebase explicitly acknowledges as unresolved ("no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake"). The attack requires no key compromise, no majority stake, and no special privileges. [8](#0-7) 

---

### Recommendation

1. **Enforce normalization at the boundary**: `stakeAboveThreshold` (or its callers) must normalize `PerasVoteStake` against the total committee stake before comparing to the relative threshold. The TODO comment already identifies the two correct remediation paths: normalize inside `stakeAboveThreshold` by accepting the total stake, or normalize before calling it.

2. **Add a zero-stake guard in `validatePerasVote`**: Reject votes whose looked-up stake is `<= 0`, analogous to the `nonZero numSeats` guard already present in `implVerifyCert` for the WFALS path.

3. **Type-level unit enforcement**: Introduce a `NormalizedPerasVoteStake` newtype (invariant: value in `[0,1]`) distinct from raw `PerasVoteStake`, so the compiler rejects unnormalized values being passed to `stakeAboveThreshold`. [9](#0-8) 

---

### Proof of Concept

**Setup**: `mkPerasParams` with `perasQuorumStakeThreshold = 3/4`, `perasQuorumStakeThresholdSafetyMargin = 2/100`. `PerasVoteStakeDistr` populated from ledger with absolute lovelace values, e.g., pool `P` has 1_000_000 lovelace → `PerasVoteStake (1000000 % 1)`.

**Step 1**: Attacker (pool `P`) sends a single `PerasVote` for target block `B` via the object-diffusion mini-protocol.

**Step 2**: `validatePerasVote mkPerasParams stakeDistr vote` looks up `P` in `stakeDistr`, finds `PerasVoteStake (1000000 % 1)`, returns `Right (ValidatedPerasVote vote (PerasVoteStake (1000000 % 1)))`.

**Step 3**: `updateCandidateVoteState` calls `votesReachQuorum cfg [validatedVote]`. `totalVoteStake = PerasVoteStake (1000000 % 1)`. `stakeAboveThreshold params totalVoteStake` evaluates `1000000 >= 0.75 + 0.02 = 0.77` → `True`.

**Step 4**: `forgePerasCert` produces a `ValidatedPerasCert` with `vpcCertBoost = PerasWeight 15`.

**Step 5**: The certificate is stored in `PerasVoteDB` and forwarded to `ChainDB`. Honest nodes add weight 15 to block `B`, preferring it over competing chains of equal or lesser weight, deviating from the canonical chain. [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-143)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L248-265)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L108-112)
```haskell
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L266-270)
```haskell
              { excessVotes
              , winnerState
              , loserStates
              }
        } -> do
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L534-536)
```haskell
              case nonZero numSeats of
                Nothing ->
                  Left (ZeroNonPersistentSeats seatIndex)
```
