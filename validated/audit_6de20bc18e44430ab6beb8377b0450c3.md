### Title
Peras Quorum Check Compares Unnormalized Absolute Stake Against Relative Threshold, Enabling Single-Vote Certificate Forgery — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares accumulated `PerasVoteStake` values — sourced from the ledger stake distribution as raw absolute quantities — against `perasQuorumStakeThreshold`, which is a relative value (3/4). No normalization step exists between the two. The code itself documents this unit mismatch as an unresolved TODO. Because absolute ledger stake values are orders of magnitude larger than 3/4, any single vote from any voter in the distribution immediately satisfies the quorum check. An unprivileged peer can therefore forge a Peras certificate with a single crafted vote message, causing incorrect chain weight boosts and corrupting chain selection on honest nodes.

---

### Finding Description

**Root cause — the uninitialized/stale-value analog:**

In the original report, `balance` was initialized to `0` and never updated before being used in `2**balance`, making the result always `1` and the subsequent modulo always `0`. The analog here is that `PerasVoteStake` is populated with a raw ledger value and never normalized before being used in the quorum comparison.

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake = unPerasVoteStake voteStake          -- raw Rational from ledger
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)  -- 3/4
  safetyMargin    = ...                        -- 2/100
```

The code itself documents the broken assumption at lines 153–161:

> *"TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."*

`PerasVoteStake` is assigned in `validatePerasVote` (lines 363–371) by a direct lookup from `PerasVoteStakeDistr` with no normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

`lookupPerasVoteStake` is a plain `Map.lookup` that returns whatever value was stored in the distribution. The companion comment on `PerasVoteStake` (lines 136–143) confirms the normalization has not been decided:

> *"At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee."*

`perasQuorumStakeThreshold` is hardcoded to `3/4` in `mkPerasParams` (line 173–174). If the distribution holds absolute ledger stake (e.g., lovelace, where a single pool may hold 10^12 or more), then `stake >> 3/4` is trivially true for every voter, and `stakeAboveThreshold` always returns `True`.

**End-to-end exploit path:**

1. Attacker connects as an unprivileged peer and sends a single `PerasVote` message naming any voter ID present in the stake distribution and any block point of their choice.
2. `processVotes` (in `ObjectPool/PerasVote.hs`, lines 178+) calls `validatePerasVote mkPerasParams sd vote`. No cryptographic signature check is performed (the default instance has a TODO stub). The voter's raw absolute stake is assigned to `vpvVoteStake`.
3. `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold` compares the absolute stake against `3/4 + 2/100`. The comparison is always `True`.
4. `forgePerasCert` is called, producing a `ValidatedPerasCert` for the attacker's chosen block.
5. The certificate is inserted into `PerasCertDB` via `addPerasCertAsync`, updating the `PerasWeightSnapshot`.
6. Chain selection (`weightedSelectView` / `preferCandidate` in `SelectView.hs`) adds `wsvWeightBoost` (the certificate's `PerasWeight`, default 15) to the attacker's chosen chain fragment.
7. Honest nodes switch to the adversarially-boosted chain, violating consensus safety.

---

### Impact Explanation

This is a **bypass of Peras voting and certificate checks** that enables unauthorized certificate acceptance and incorrect chain selection. A single crafted vote from an unprivileged peer causes a Peras certificate to be forged for an arbitrary block, granting it a weight boost of `perasWeight = 15` (default). Chain selection (`preferCandidate`) then prefers this artificially-heavier chain over the honest canonical chain. This is a consensus safety failure: honest nodes permanently diverge to an adversarially-chosen fork without any legitimate quorum having been reached.

**Impact: Critical** — matches "Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."

---

### Likelihood Explanation

The entry point is the standard Peras vote miniprotocol, reachable by any peer without credentials. The condition (absolute ledger stake >> 3/4) holds for every voter with non-trivial stake. The code's own TODO comment confirms the normalization is missing and the comparison is known to be unit-unsafe. No privilege, key material, or stake majority is required.

**Likelihood: High.**

---

### Recommendation

Normalize `PerasVoteStake` before it reaches `stakeAboveThreshold`. Either:

1. Divide each voter's absolute stake by the total active stake when populating `PerasVoteStakeDistr`, so stored values are already in `[0,1]`; or
2. Modify `stakeAboveThreshold` to accept the total stake as an additional parameter and perform the division internally before comparing against the relative threshold.

The existing comment at lines 153–161 already prescribes exactly this fix. The normalization must be applied before `validatePerasVote` stores the stake in `ValidatedPerasVote`, so that every downstream caller of `stakeAboveThreshold` (including `votesReachQuorum`, `updateLoserVoteState`, and the `PerasVoteDB` model) operates on consistent units.

---

### Proof of Concept

```
Attacker (unprivileged peer):
  1. Observe any PerasVoterId present in the node's stake distribution
     (e.g., from a public pool registry or chain state query).
  2. Craft PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = V }
     where B is any block the attacker wants to boost.
  3. Send the vote via the Peras vote miniprotocol.

Node (victim):
  processVotes → validatePerasVote:
    stake = lookupPerasVoteStake V stakeDistr
    -- stake is absolute, e.g. 1_000_000_000_000 (lovelace)
    vpvVoteStake = PerasVoteStake (1_000_000_000_000 % 1)

  updateCandidateVoteState → votesReachQuorum → stakeAboveThreshold:
    1_000_000_000_000 >= (3/4) + (2/100)   -- True, always

  forgePerasCert → ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }
  addPerasCertAsync → PerasCertDB updated → PerasWeightSnapshot updated

  Chain selection:
    wsvTotalWeight(B's chain) = blockNo + 15  -- boosted
    preferCandidate: ShouldSwitch → node adopts attacker's chain
```

**Structural analog to the original report:**

| Original (`StakingSystem.sol`) | This finding (`SupportsPeras.hs`) |
|---|---|
| `balance = 0` (never updated) | `PerasVoteStake` = absolute ledger value (never normalized) |
| `2 ** balance = 2 ** 0 = 1` | `stake = 1_000_000_000_000` |
| `randomness % 1 = 0` always | `1_000_000_000_000 >= 3/4` always `True` |
| Navies never steal gold | Quorum always reached with one vote |
| Pirates keep all gold | Attacker forges certificate for any block | [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L418-424)
```haskell
freshTargetVoteTally :: PerasVoteTarget blk -> PerasTargetVoteTally blk
freshTargetVoteTally target =
  PerasTargetVoteTally
    { ptvtTarget = target
    , ptvtVotes = Map.empty
    , ptvtTotalStake = PerasVoteStake 0
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-113)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
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
