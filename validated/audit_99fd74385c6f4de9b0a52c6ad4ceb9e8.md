### Title
Peras Quorum Bypass via Absolute-vs-Relative Stake Unit Mismatch in `stakeAboveThreshold` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (which can be an absolute ledger stake, e.g. in Lovelace) against a `perasQuorumStakeThreshold` that is defined as a **relative** fraction of total committee stake. Because no normalization step exists between vote validation and quorum checking, a single vote carrying any absolute stake value larger than the relative threshold (e.g. `> 0.75`) immediately satisfies quorum. This is the direct analog of the DCA `inAmount` bug: a total/absolute quantity is used where a per-unit/normalized quantity is required.

---

### Finding Description

`PerasVoteStake` is a bare `Rational` with no type-level distinction between absolute and relative units. The code itself documents the problem:

```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting committee (given that the quorum is expressed as
-- a relative value of the voting committee total stake).
``` [1](#0-0) 

`stakeAboveThreshold` then directly compares the raw `PerasVoteStake` against the relative quorum threshold without any normalization:

```haskell
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units...
-- this function only makes sense when both values are relative (normalized)
-- values, so we should either normalize the 'PerasVoteStake' before calling
-- this function, or change this function to accept a stake distribution and
-- perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [2](#0-1) 

`votesReachQuorum` sums the raw `vpvVoteStake` fields and passes the total directly to `stakeAboveThreshold` with no normalization step:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [3](#0-2) 

`votesReachQuorum` is called from `updateCandidateVoteState` in the vote aggregation engine:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [4](#0-3) 

The `validatePerasVote` degenerate instance assigns the stake from `PerasVoteStakeDistr` directly to `vpvVoteStake` without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [5](#0-4) 

The inbound vote diffusion handler wires this together. Currently it uses an empty `PerasVoteStakeDistr` as a placeholder, but the comment explicitly states this will be replaced with real ledger stake data:

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
(pure (PerasVoteStakeDistr mempty))
``` [6](#0-5) 

When the real ledger stake distribution is wired in (as the TODO requires), it will naturally contain absolute Lovelace values. A voter with even 1 Lovelace of stake would have `PerasVoteStake = 1 % 1`. The quorum threshold is a relative value such as `3 % 4` (75%). The comparison `1 >= 0.75` is `True`, so **a single vote from any voter with any positive stake immediately satisfies quorum**.

The `stakeAboveThreshold` function is also called in `updateLoserVoteState`, meaning the same mismatch would incorrectly trigger the `RoundVoteStateLoserAboveQuorum` error path:

```haskell
let aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
``` [7](#0-6) 

---

### Impact Explanation

**Critical.** Bypass of Peras voting and certificate checks. An unprivileged peer can send a single crafted `PerasVote` message for any block of their choice. Once the real stake distribution is wired in, `validatePerasVote` will assign the voter's absolute ledger stake (e.g. `1000000 % 1` Lovelace) to `vpvVoteStake`. `stakeAboveThreshold` will compare this against the relative quorum threshold (e.g. `3 % 4`), find `1000000 >= 0.75`, and immediately forge a `ValidatedPerasCert` for the attacker's chosen block. This certificate is then stored in the `PerasVoteDB` and propagated to the `ChainDB`, where it boosts the adversarial block's chain weight by `perasWeight`, causing honest nodes to prefer the adversarially-boosted chain over the canonical chain. This directly undermines Peras's finality guarantee.

---

### Likelihood Explanation

**High** once the real stake distribution plumbing is completed. The TODO comment in `NodeToNode.hs` explicitly states this wiring is planned. The `makePerasVotePoolWriterFromVoteDB` function (used in tests and the non-ChainDB path) already accepts an arbitrary `STM m PerasVoteStakeDistr`, and the smoke test populates it with already-relative values only by convention, not by enforcement. There is no type-level or runtime guard preventing absolute values from being stored in `PerasVoteStakeDistr`. The vulnerability is latent in all current production code paths and will become immediately exploitable when the ledger stake distribution is connected.

---

### Recommendation

1. **Enforce units at the type level**: introduce a `NormalizedPerasVoteStake` newtype distinct from `PerasVoteStake` and require `stakeAboveThreshold` to accept only the normalized form.
2. **Normalize at the validation boundary**: `validatePerasVote` (or the pool writer) must divide each voter's absolute ledger stake by the total committee stake before storing it in `vpvVoteStake`.
3. **Do not defer normalization**: the TODO comment acknowledges the gap; it must be resolved before the real stake distribution is wired in, not after.
4. **Add a property test**: assert that for any `PerasVoteStakeDistr` whose values sum to 1 (normalized), `stakeAboveThreshold` behaves correctly, and that for any distribution whose values sum to a large absolute number, a single-voter quorum is impossible.

---

### Proof of Concept

Assume `mkPerasParams` sets `perasQuorumStakeThreshold = 3 % 4` and `perasQuorumStakeThresholdSafetyMargin = 0`.

When the real stake distribution is wired in with absolute Lovelace values:

```
stakeDistr = PerasVoteStakeDistr { voter_A -> PerasVoteStake (1_000_000 % 1) }
```

Attacker sends one `PerasVote` for block `B` from `voter_A`.

`validatePerasVote` assigns `vpvVoteStake = PerasVoteStake (1_000_000 % 1)`.

`votesReachQuorum` computes:
```
totalVoteStake = PerasVoteStake (1_000_000 % 1)
stakeAboveThreshold: 1_000_000 >= (3/4 + 0)  →  True
```

`forgePerasCert` is called, producing a `ValidatedPerasCert` boosting block `B` by `perasWeight`. The certificate is stored and diffused, causing all honest nodes to add `perasWeight` to block `B`'s chain score, potentially making an adversarial chain the preferred chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L582-587)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L400-408)
```haskell
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```
