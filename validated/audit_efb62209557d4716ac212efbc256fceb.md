### Title
Peras Quorum Check Compares Unnormalized Absolute Vote Stake Against Relative Threshold, Enabling Certificate Forgery - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value directly against a relative `Rational` quorum threshold without any normalization step. The code itself documents that this comparison "only makes sense when both values are relative (normalized) values," yet no normalization is performed anywhere in the vote-validation pipeline. If the `PerasVoteStakeDistr` supplied to `validatePerasVote` carries absolute ledger-stake values (the natural representation from the Cardano ledger, and the only representation currently discussed), any single vote from a voter with positive stake will trivially satisfy the quorum check, causing the node to forge a Peras certificate for an adversary-chosen block and boost it in chain selection.

---

### Finding Description

**Root cause — `stakeAboveThreshold` (lines 162–173):**

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
```

`PerasVoteStake` is a bare `Rational` newtype. The quorum threshold (`perasQuorumStakeThreshold`) is also a `Rational` intended to represent a fraction of total stake (e.g. `3 % 4`). No normalization divides the accumulated vote stake by the total stake before the comparison.

**How vote stake is assigned — `validatePerasVote` (lines 363–371):**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The `vpvVoteStake` field is set directly to whatever `Rational` is stored in `PerasVoteStakeDistr` for that voter. There is no normalization, no signature check, and no cross-check against total stake. The comment on `PerasVoteStake` itself states: *"there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee."*

**Quorum accumulation — `votesReachQuorum` (lines 242–272) and `updateCandidateVoteState` (lines 577–587):**

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
```

If `PerasVoteStakeDistr` is populated with absolute lovelace values (e.g. a voter with 1 000 000 lovelace has stake `1000000 % 1`), then `totalVoteStake` after even one vote is `1000000`, which is trivially `>= 0.75 + safetyMargin`. The node immediately forges a `ValidatedPerasCert` for the attacker's chosen block.

**Vote diffusion entry point — `makePerasVotePoolWriterFromChainDB` (lines 131–148):**

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

Inbound `PerasVote` objects received from any peer are validated here. Because `validatePerasVote` performs no signature verification (the TODO comment at line 350 confirms this), an attacker only needs to know a valid `PerasVoterId` present in the stake distribution (publicly derivable from the ledger) to submit a vote that passes validation.

---

### Impact Explanation

A single crafted `PerasVote` message from an unprivileged peer, naming any pool ID present in the stake distribution, causes the receiving node to:

1. Accept the vote (no signature check).
2. Assign the voter's absolute ledger stake as `vpvVoteStake`.
3. Evaluate `stakeAboveThreshold` with an absolute value >> 1 against a relative threshold < 1 → always `True`.
4. Forge a `ValidatedPerasCert` boosting the attacker's chosen block with `perasWeight`.
5. Apply that boost in chain selection, preferring the adversarially chosen block over the honest canonical chain.

This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain by sending a single vote message, without any stake, key material, or privileged access.

---

### Likelihood Explanation

The normalization gap is explicitly documented in two separate TODO comments in production code. The `PerasVoteStakeDistr` is populated from an external STM action (`getStakeDistrSTM`) with no normalization visible anywhere in the codebase. The natural ledger representation is absolute lovelace, making the mismatch the default state. Any peer connected via the vote-diffusion mini-protocol can trigger this path.

---

### Recommendation

1. **Normalize before comparison.** Either divide each `vpvVoteStake` by the total stake in `PerasVoteStakeDistr` before calling `stakeAboveThreshold`, or change `stakeAboveThreshold` to accept the total stake and perform the division internally.
2. **Enforce units at the type level.** Introduce a `NormalizedPerasVoteStake` newtype (a value in `[0,1]`) distinct from raw `LedgerStake`, and require callers to produce it via an explicit normalization function that takes the total stake as input.
3. **Add signature verification to `validatePerasVote`.** The current degenerate instance accepts any vote for any voter ID without verifying the cryptographic signature, compounding the risk.
4. **Implement `getVotingCommitteeForElection`** in `AcrossEpochs.hs` so that vote/certificate verification uses the correct epoch's committee rather than crashing.

---

### Proof of Concept

```
Precondition: node is running with a PerasVoteStakeDistr populated with
absolute lovelace values (e.g. pool P has 1_000_000 lovelace → stake = 1000000 % 1).
Quorum threshold = 3 % 4.

1. Attacker queries the ledger for any PerasVoterId with positive stake → finds pool P.
2. Attacker constructs:
     PerasVote { pvVoteRound = R, pvVoteBlock = <adversarial block B>, pvVoteVoterId = P }
   No signing key required (validatePerasVote performs no signature check).
3. Attacker sends this vote to the target node via the Peras vote diffusion protocol.
4. Node calls validatePerasVote: lookupPerasVoteStake returns 1000000 % 1 → vote accepted.
5. updateCandidateVoteState calls votesReachQuorum:
     totalVoteStake = 1000000 % 1
     stakeAboveThreshold: 1000000 >= (3%4) + safetyMargin → True
6. forgePerasCert is called → ValidatedPerasCert for block B with boost perasWeight.
7. Chain selection now prefers block B over the honest canonical tip.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-271)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```
