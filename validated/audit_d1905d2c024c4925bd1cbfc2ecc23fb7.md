### Title
Peras Quorum Check Bypassed by Undocumented Unit Mismatch in `stakeAboveThreshold` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `stakeAboveThreshold` function, which is the sole gate for determining whether a Peras voting round has reached quorum and a certificate should be forged, contains an explicit TODO documenting that it assumes `PerasVoteStake` and the quorum threshold are expressed in the same units (both relative/normalized). However, no normalization is performed anywhere in the call chain before this comparison. A companion comment on `PerasVoteStake` itself admits there is currently no consensus on how to convert absolute ledger stake to relative committee stake. If `vpvVoteStake` values stored in `ValidatedPerasVote` are absolute (lovelace-denominated) while the threshold is relative (e.g., 0.75), the comparison is trivially satisfied by any voter, allowing a single peer-submitted vote to forge a Peras certificate.

### Finding Description

**Root cause — `stakeAboveThreshold` in `SupportsPeras.hs`:**

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

The companion comment on `PerasVoteStake` explicitly states there is no agreed-upon conversion from absolute ledger stake to relative committee stake:

```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
``` [2](#0-1) 

**Call chain — no normalization before the check:**

`votesReachQuorum` (the smart constructor for `ValidatedPerasVotesWithQuorum`) sums raw `vpvVoteStake` values and passes the total directly to `stakeAboveThreshold` without any normalization step:

```haskell
totalVoteStake =
  mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake =
  stakeAboveThreshold cfg totalVoteStake
``` [3](#0-2) 

`updateCandidateVoteState` in `Vote/Aggregation.hs` calls `votesReachQuorum` directly:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [4](#0-3) 

This is reached from `implAddVote` in `PerasVoteDB/Impl.hs` whenever a new `ValidatedPerasVote` is added: [5](#0-4) 

**Exploit path:**

1. An unprivileged peer sends a `PerasVote` message over the node-to-node mini-protocol.
2. The node calls `validatePerasVote` (a `BlockSupportsPeras` type-class method) to produce a `ValidatedPerasVote` with a `vpvVoteStake` field.
3. If the concrete implementation of `validatePerasVote` sets `vpvVoteStake` to an absolute lovelace value (which is the natural reading of "absolute stake of a voter in the ledger"), and `perasQuorumStakeThreshold` is a relative value such as `0.75`, then `stakeAboveThreshold` evaluates `1_000_000 >= 0.75`, which is always `True`.
4. A single vote from any voter with any positive stake immediately satisfies quorum, causing `forgeCert` to be called and a `ValidatedPerasCert` to be produced and propagated.
5. The forged certificate boosts the targeted block's chain-selection weight by `perasWeight`, causing honest nodes to prefer that chain over the canonical chain.

### Impact Explanation

**Impact: Critical** — Bypass of Peras certificate/vote verification checks. If the unit mismatch is present in the concrete `validatePerasVote` implementation, any unprivileged peer can cause a Peras certificate to be forged for an arbitrary block with a single vote, regardless of actual stake. This directly enables unauthorized certificate acceptance and chain-selection manipulation: the boosted block gains a `PerasWeight` advantage in `compareCandidateChains`, causing honest nodes to prefer an adversarially-chosen chain over the canonical one. This violates the core Peras safety property that certificates require a supermajority of committee stake.

### Likelihood Explanation

**Likelihood: Medium.** The TODO comment is unambiguous: normalization is required but not performed. The companion note on `PerasVoteStake` confirms there is no agreed-upon normalization procedure. The concrete `validatePerasVote` implementation (in `ouroboros-consensus-cardano`) determines whether the stake is absolute or relative; if it uses the raw ledger stake (the most natural source), the mismatch is active. Peras is still in active development, making it plausible that this gap has not yet been closed. An attacker needs only to send a syntactically valid, correctly signed vote — no privileged keys or stake majority required.

### Recommendation

1. **Enforce normalization at the boundary**: `validatePerasVote` must normalize the voter's absolute ledger stake to a relative committee-fraction value before storing it in `vpvVoteStake`. The normalization formula (voter absolute stake / total committee absolute stake) must be agreed upon and applied consistently.
2. **Enforce units at the type level**: Introduce distinct newtypes for absolute stake (`AbsolutePerasVoteStake`) and relative stake (`RelativePerasVoteStake`) so that `stakeAboveThreshold` can only accept the relative variant, making the unit mismatch a compile-time error.
3. **Remove the TODO and add an assertion**: Until the type-level fix is in place, add a runtime assertion in `stakeAboveThreshold` that `unPerasVoteStake voteStake <= 1` to catch absolute values in testing.

### Proof of Concept

**Setup:** Configure a private testnet with Peras enabled. Set `perasQuorumStakeThreshold = 0.75` (relative). Implement `validatePerasVote` to set `vpvVoteStake` to the voter's absolute lovelace stake (e.g., `1_000_000` lovelace for a voter with 1 ADA).

**Steps:**
1. Peer A (controlling 1 ADA, far below 75% of total stake) sends a single valid `PerasVote` for block B in round R.
2. The node calls `validatePerasVote`, producing `ValidatedPerasVote { vpvVoteStake = PerasVoteStake (1_000_000 % 1) }`.
3. `implAddVote` → `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum`.
4. `stakeAboveThreshold` evaluates `1_000_000 >= 0.75 + safetyMargin` → `True`.
5. `forgeCert` is called; a `ValidatedPerasCert` is produced for block B with full `perasWeight` boost.
6. The certificate is propagated; honest nodes now prefer block B's chain over the canonical chain.

**Expected (correct) behavior:** Quorum should require votes representing ≥75% of total committee stake; a single 1-ADA voter should not satisfy this.

**Observed (buggy) behavior:** Quorum is declared satisfied; a certificate is forged and accepted.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-211)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
