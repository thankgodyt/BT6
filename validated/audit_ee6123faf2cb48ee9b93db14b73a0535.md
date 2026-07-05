### Title
Peras Quorum Check Compares Unnormalized Vote Stake Against Relative Threshold, Enabling Unauthorized Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in `SupportsPeras.hs` compares accumulated `PerasVoteStake` values directly against the relative `perasQuorumStakeThreshold` without normalizing the vote stake to the same unit. The code itself documents this as an unresolved unit-mismatch: vote stake may be absolute (raw ledger lovelace) while the quorum threshold is a relative fraction. This is the same class of bug as the external report — a value is compared against a threshold using the wrong base — and the consequence is that the quorum gate for Peras certificate forging is either trivially bypassed (if absolute stake >> threshold) or permanently unreachable (if stake fraction << threshold), both of which break the Peras voting invariant.

---

### Finding Description

`stakeAboveThreshold` is the sole gate that decides whether accumulated votes reach quorum and a `ValidatedPerasCert` is forged:

```haskell
-- SupportsPeras.hs lines 153-173
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

The `PerasVoteStake` assigned to each validated vote comes directly from `PerasVoteStakeDistr` via `lookupPerasVoteStake`, with no normalization step:

```haskell
-- lines 363-371
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [2](#0-1) 

`votesReachQuorum` then sums these raw stakes and calls `stakeAboveThreshold`:

```haskell
-- lines 267-270
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [3](#0-2) 

The `perasQuorumStakeThreshold` is a relative `Rational` (e.g. `0.75` for 75% of total committee stake):

```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
``` [4](#0-3) 

Meanwhile, the `PerasVoteStakeDistr` is populated from the ledger's absolute stake distribution. The code explicitly acknowledges the unresolved unit mismatch:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [5](#0-4) 

The WFALS committee's `implEligiblePartyVoteWeight` further confirms the inconsistency: persistent members receive their raw `LedgerStake` as vote weight (not normalized by total stake), while non-persistent members receive a value normalized only by `totalNonPersistentStake` — not by the full committee stake:

```haskell
WFALSPersistentMember _seatIndex (LedgerStake stake) ->
  VoteWeight stake   -- raw absolute stake, NOT normalized
``` [6](#0-5) 

---

### Impact Explanation

**Scenario A — absolute stake >> relative threshold (most dangerous):**
If `PerasVoteStake` values are absolute lovelace (e.g. a pool with 1,000,000 lovelace has `PerasVoteStake = 1000000`) and `perasQuorumStakeThreshold = 0.75`, then `1000000 >= 0.75` is trivially true. A **single adversarial voter** with any positive stake can call `votesReachQuorum` and have it return `Just`, causing `forgePerasCert` to produce a `ValidatedPerasCert` for any block they choose. This certificate is then accepted by the ChainDB and applied as a weight boost via `wsvTotalWeight`, directly manipulating chain selection in favor of the adversary's preferred chain.

**Scenario B — stake fraction << threshold (quorum never reachable):**
If stake values are stored as small fractions (e.g. `0.001`) but the threshold is a large absolute value, quorum can never be reached, permanently disabling the Peras boosting mechanism and degrading chain security to base Praos.

Both scenarios break the Peras voting invariant. Scenario A is the critical path: it allows an unprivileged peer to trigger unauthorized certificate forging by simply sending a valid vote message through the vote diffusion miniprotocol. [7](#0-6) 

---

### Likelihood Explanation

The vote diffusion path is fully reachable by any unprivileged peer via the `ObjectDiffusion` miniprotocol. The `makePerasVotePoolWriterFromChainDB` function processes incoming votes from peers, validates them (assigning the raw stake from `PerasVoteStakeDistr`), and adds them to the ChainDB, which triggers certificate forging if `votesReachQuorum` returns `Just`. No special privileges, key compromise, or stake majority is required — only a valid vote from a registered pool. [8](#0-7) 

---

### Recommendation

1. **Normalize `PerasVoteStake` before comparison.** Before calling `stakeAboveThreshold`, divide each voter's absolute stake by the total committee stake to produce a relative value in `[0,1]`. This should be done inside `validatePerasVote` or inside `votesReachQuorum` once the total stake is known.

2. **Enforce units at the type level.** Introduce distinct newtypes for absolute stake (`AbsolutePerasVoteStake`) and relative stake (`RelativePerasVoteStake`) so that `stakeAboveThreshold` can only accept the normalized form, making unit mismatches a compile-time error.

3. **Resolve the open research question.** The comment at line 136 acknowledges that researchers and engineers have not agreed on the normalization method. This must be resolved before Peras is deployed on mainnet, as the current placeholder comparison is unsound.

---

### Proof of Concept

Consider a private testnet with:
- `perasQuorumStakeThreshold = 0.75` (75% of committee stake)
- Pool A with absolute ledger stake = 1,000,000 lovelace, stored as `PerasVoteStake (1000000 % 1)` in `PerasVoteStakeDistr`

Pool A sends a single vote for block B. The node:
1. Calls `validatePerasVote`, which looks up `PerasVoteStake (1000000 % 1)` and assigns it to `vpvVoteStake`.
2. Calls `votesReachQuorum` with `[ValidatedPerasVote { vpvVoteStake = 1000000 % 1 }]`.
3. Computes `totalVoteStake = 1000000 % 1`.
4. Calls `stakeAboveThreshold`: `(1000000 % 1) >= (75 % 100) + safetyMargin` → `True`.
5. Calls `forgePerasCert`, producing a `ValidatedPerasCert` with `vpcCertBoost = perasWeight`.
6. The ChainDB applies the weight boost to block B, making it preferred over the honest chain tip.

Pool A has bypassed the 75% quorum requirement with a single vote, forging a certificate that manipulates chain selection. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L94-98)
```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L412-417)
```haskell
implEligiblePartyVoteWeight committee = \case
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
