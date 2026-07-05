### Title
Peras Quorum Certificate Bypass via Unit Mismatch in `stakeAboveThreshold` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function directly compares accumulated `PerasVoteStake` values against `perasQuorumStakeThreshold` (a normalized relative fraction, e.g. `3/4`) without any normalization step. The code itself carries an explicit TODO acknowledging that the two operands may be in different units (absolute vs. relative). When the real ledger stake distribution is wired in with absolute lovelace values, any single vote from any pool with positive stake trivially satisfies the quorum check, enabling unauthorized Peras certificate forging and chain-selection manipulation.

---

### Finding Description

`PerasVoteStake` is a bare `Rational` newtype with no invariant enforcing that it is normalized (i.e., in `[0,1]`):

```haskell
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational }
``` [1](#0-0) 

The quorum check compares the accumulated vote stake directly against the threshold:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [2](#0-1) 

The threshold is set to `3/4` (a relative fraction):

```haskell
perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
perasQuorumStakeThresholdSafetyMargin = PerasQuorumStakeThresholdSafetyMargin (2 / 100)
``` [3](#0-2) 

The code itself acknowledges the unit mismatch in a TODO comment immediately above `stakeAboveThreshold`:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units. That is, both are either absolute or relative (normalized) values. Under the current implementation of `PerasParams`, this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [4](#0-3) 

The `validatePerasVote` default instance assigns the stake value directly from `PerasVoteStakeDistr` without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [5](#0-4) 

The production vote diffusion path (`makePerasVotePoolWriterFromChainDB`) currently passes an empty distribution as a placeholder, making the bug dormant:

```haskell
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [6](#0-5) 

However, the TODO comments in both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` explicitly state that the real ledger stake distribution will be wired in:

> "In the future, we won't read it from the stake distr directly, but rather use the committee selection data" [7](#0-6) 

When that happens, if absolute lovelace values are used (the natural representation from the ledger), the comparison `1_000_000 >= 3/4 + 2/100` is always `True`, and every single vote trivially reaches quorum.

---

### Impact Explanation

An unprivileged peer sends a single `PerasVote` via the Peras vote diffusion miniprotocol. Once the real stake distribution is wired in with absolute lovelace values:

1. `validatePerasVote` accepts the vote with `PerasVoteStake (lovelace_amount % 1)`.
2. `stakeAboveThreshold` evaluates `lovelace_amount >= 77/100` → always `True` for any positive stake.
3. `votesReachQuorum` returns `Just votesWithQuorum` after a single vote.
4. `forgePerasCert` creates a certificate for the adversarially chosen block.
5. The block receives a chain-selection boost of `perasWeight = 15`.

This is a **bypass of Peras certificate checks** enabling unauthorized certificate acceptance and chain-selection manipulation — an honest node is made to prefer an adversarially boosted block. [8](#0-7) 

---

### Likelihood Explanation

**Medium.** The vulnerability is currently dormant because the production code uses `PerasVoteStakeDistr mempty`. However, the code is explicitly designed to be completed with real ledger stake data (multiple TODO comments confirm this), and the unit mismatch will manifest at that point unless normalization is added. The entry path (Peras vote diffusion miniprotocol) is already wired into the node-to-node protocol handlers and reachable by any unprivileged peer.

---

### Recommendation

Enforce normalization at the boundary where `PerasVoteStakeDistr` is populated from the ledger. Concretely, either:

1. **Normalize inside `stakeAboveThreshold`**: accept the total committee stake as an additional parameter and compute `stake / totalStake >= quorumThreshold + safetyMargin`.
2. **Enforce via smart constructor**: introduce a `mkPerasVoteStakeDistr` that normalizes all values to `[0,1]` before storing them, and remove the direct `PerasVoteStakeDistr` constructor from the public API.
3. **Use distinct types**: introduce separate `AbsolutePerasVoteStake` and `RelativePerasVoteStake` newtypes so the type system prevents the comparison from compiling when units differ.

The existing TODO comment at lines 155–161 of `SupportsPeras.hs` already identifies the correct fix direction.

---

### Proof of Concept

```
-- Attacker-controlled scenario (private testnet / local reproduction):
-- 1. Populate PerasVoteStakeDistr with attacker's pool having absolute stake:
let stakeDistr = PerasVoteStakeDistr $
      Map.singleton attackerVoterId (PerasVoteStake (1_000_000 % 1))
-- 2. Send a single PerasVote for a target block via the vote diffusion miniprotocol.
-- 3. validatePerasVote assigns vpvVoteStake = PerasVoteStake (1000000 % 1).
-- 4. stakeAboveThreshold evaluates:
--      1000000 >= (3/4) + (2/100)   -- i.e., 1000000 >= 0.77  → True
-- 5. votesReachQuorum returns Just votesWithQuorum after ONE vote.
-- 6. forgePerasCert produces a ValidatedPerasCert boosting the target block by perasWeight=15.
-- 7. Chain selection on the honest node now prefers the adversarially boosted block.
``` [2](#0-1) [3](#0-2)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L402-408)
```haskell
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L107-113)
```haskell
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```
