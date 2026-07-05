### Title
Peras Quorum Threshold Comparison Uses Mismatched Units, Allowing Sub-Quorum Certificate Acceptance - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (which may carry absolute ledger stake in lovelace) against `perasQuorumStakeThreshold` (a relative/normalized `Rational` such as `3/4`). The quorum threshold parameter exists and is used in the comparison, but because no normalization is performed before the comparison, the check does not actually enforce the intended safety bound. Any voter whose absolute stake exceeds `0.77` (the default threshold + safety margin) trivially passes the quorum gate, allowing a single inbound vote from an unprivileged peer to forge a Peras certificate for an arbitrary block.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` is the sole gatekeeper that decides whether accumulated votes have reached the Peras quorum required to forge a certificate:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The function's own TODO comment acknowledges the unit mismatch:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `PerasVoteStake` type itself is documented as unresolved:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [3](#0-2) 

The `validatePerasVote` stub (the only production implementation) ignores `_params` entirely and assigns the raw lookup result from `PerasVoteStakeDistr` directly to `vpvVoteStake` without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

The default `mkPerasParams` sets the quorum threshold as a relative value `3/4`:

```haskell
perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
perasQuorumStakeThresholdSafetyMargin = PerasQuorumStakeThresholdSafetyMargin (2 / 100)
``` [5](#0-4) 

The inbound vote processing path in `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote` using the hardcoded default params and the raw stake distribution: [6](#0-5) 

When `PerasVoteStakeDistr` is populated from the ledger's absolute stake distribution (lovelace amounts), a voter with even a modest absolute stake (e.g., `1_000_000` lovelace) produces a `PerasVoteStake` of `1000000 :: Rational`. The comparison `1000000 >= 0.75 + 0.02` trivially passes, so a single vote from any non-trivial stake pool immediately satisfies the quorum check and causes `votesReachQuorum` to return `Just`, triggering certificate forging. [7](#0-6) 

---

### Impact Explanation

This is a **bypass of Peras certificate/vote verification**. The quorum threshold parameter (`perasQuorumStakeThreshold`) is used in the comparison but does not actually enforce the intended safety bound due to the unit mismatch. A single inbound `PerasVote` from an unprivileged peer — for any block the attacker chooses — can cause the receiving node to forge a `ValidatedPerasCert` for that block. The forged certificate applies a `PerasWeight` boost (default: 15) to the attacker's chosen block in chain selection, potentially causing the node to prefer an adversarially chosen chain over the honest chain. This maps to: **Bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance**.

---

### Likelihood Explanation

The attack is reachable via the object diffusion mini-protocol, which is the standard peer-to-peer path for receiving Peras votes. No special privileges are required — any peer that knows a valid `PerasVoterId` (a stake pool key hash, which is public on-chain) can send a vote. The unit mismatch is not a hypothetical: the code explicitly documents that the stake distribution comes from the ledger (absolute lovelace), while the threshold is relative (`3/4`). The mismatch is present in the only production implementation of `validatePerasVote` and `stakeAboveThreshold`.

---

### Recommendation

1. **Normalize `PerasVoteStake` before the threshold comparison.** Either normalize the raw ledger stake to a relative value (dividing by total committee stake) inside `validatePerasVote`, or pass the total stake distribution into `stakeAboveThreshold` and perform normalization there.
2. **Enforce the unit contract at the type level.** Introduce distinct newtypes for absolute stake and relative/normalized stake so that the compiler prevents mixing them in arithmetic comparisons.
3. **Remove the `_params` underscore** in `validatePerasVote` once the normalization logic is in place, so that the quorum threshold is actually consulted during per-vote validation.
4. **Add a property test** asserting that `stakeAboveThreshold` returns `False` when the sum of all individual votes is below the quorum fraction of total committee stake.

---

### Proof of Concept

**Setup**: A private testnet with Peras enabled. The `PerasVoteStakeDistr` is populated from the ledger with absolute lovelace values (e.g., a stake pool with `2_000_000` lovelace).

**Steps**:
1. Peer A sends a single `PerasVote` for block `B` (an adversarially chosen block) via the object diffusion protocol.
2. The receiving node calls `validatePerasVote mkPerasParams sd vote`. The voter's absolute stake `2_000_000 :: Rational` is assigned to `vpvVoteStake`.
3. The vote is added to `PerasVoteDB`. `updatePerasRoundVoteStates` calls `votesReachQuorum`, which calls `stakeAboveThreshold`.
4. The comparison `2_000_000 >= 0.75 + 0.02` evaluates to `True`.
5. `votesReachQuorum` returns `Just`, and `forgePerasCert` is called, producing a `ValidatedPerasCert` for block `B`.
6. The certificate is stored and applied to chain selection, giving block `B` a weight boost of 15, potentially causing the node to prefer the adversary's chain.

The root cause is at:
- `stakeAboveThreshold` — no normalization before comparison [1](#0-0) 
- `validatePerasVote` — raw stake assigned without normalization [8](#0-7) 
- `votesReachQuorum` — calls `stakeAboveThreshold` with the unnormalized total [9](#0-8) 
- `mkPerasParams` — threshold is relative `3/4` while stake may be absolute [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-161)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L138-142)
```haskell
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```
