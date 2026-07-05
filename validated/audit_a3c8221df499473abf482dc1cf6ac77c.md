### Title
Absolute-vs-Relative Unit Mismatch in `stakeAboveThreshold` Trivially Bypasses Peras Quorum — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` drawn from the **absolute** ledger stake distribution against a **relative** (normalized) quorum threshold of `3/4 + 2/100 = 0.77`. Because any voter's absolute stake (e.g., `1000 ADA` represented as the rational `1000`) is always greater than `0.77`, a single vote from any voter with positive stake trivially satisfies the quorum check. This allows an unprivileged peer to forge a Peras certificate for an arbitrary block with one vote, bypassing the quorum requirement entirely.

---

### Finding Description

`PerasVoteStake` is populated by `validatePerasVote` via a direct `Map.lookup` into `PerasVoteStakeDistr`, which holds raw ledger stake values:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [1](#0-0) 

The code comment on `PerasVoteStake` explicitly acknowledges that no normalization is performed:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [2](#0-1) 

`stakeAboveThreshold` then compares this absolute value directly against the relative threshold:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

with `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`, giving a combined threshold of `0.77`. [3](#0-2) [4](#0-3) 

The TODO comment on `stakeAboveThreshold` itself confirms the assumption is violated:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [5](#0-4) 

`votesReachQuorum` calls `stakeAboveThreshold` to decide whether to forge a certificate:

```haskell
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [6](#0-5) 

This is called from `updateCandidateVoteState` inside `updatePerasRoundVoteStates`, which is the core vote-aggregation path triggered on every inbound vote: [7](#0-6) 

The forged certificate is stored in the `PerasVoteDB` and subsequently used to boost blocks in chain selection via `weightBoostOfFragment` / `totalWeightOfFragment`: [8](#0-7) 

The inbound vote path that exposes this to an unprivileged peer is `makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB`, which call `validatePerasVote` and then `PerasVoteDB.addVote`: [9](#0-8) 

---

### Impact Explanation

**High — chain selection bug.** A single vote from any voter with positive absolute ledger stake (e.g., `1000 ADA` → rational `1000`) satisfies `1000 >= 0.77`, causing `votesReachQuorum` to return `Just` and `updateCandidateVoteState` to forge a certificate immediately. The forged certificate applies a `perasWeight = 15` boost to the adversary's chosen block. An honest node receiving this vote via the ObjectDiffusion mini-protocol will prefer the adversary's boosted chain over the canonical chain, constituting a chain-selection manipulation beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

**High.** The entry path is the standard ObjectDiffusion peer-to-peer vote propagation protocol, reachable by any connected peer. No special privileges, key compromise, or stake majority is required — only a single valid vote from any registered stake pool. The unit mismatch is unconditional and affects every vote processed.

---

### Recommendation

Normalize `PerasVoteStake` to a relative value (dividing each voter's absolute stake by the total stake in `PerasVoteStakeDistr`) before it is stored in `ValidatedPerasVote.vpvVoteStake`, or pass the total stake into `stakeAboveThreshold` and perform the normalization there. The fix should be applied at the `validatePerasVote` call site so that the invariant "stake is relative" is enforced at the boundary where votes enter the system.

Concretely, `lookupPerasVoteStake` (or its caller) should compute:

```haskell
relativeStake = absoluteStake / totalStakeInDistribution
```

before assigning `vpvVoteStake`, ensuring the comparison in `stakeAboveThreshold` is between two values in `[0, 1]`.

---

### Proof of Concept

**Setup:**
- Ledger stake distribution: `{ Alice → 1000 ADA, Bob → 500 ADA, Carol → 500 ADA }` (total = 2000 ADA)
- `PerasVoteStakeDistr` stores absolute values: `{ Alice → 1000, Bob → 500, Carol → 500 }`
- `perasQuorumStakeThreshold = 3/4`, `perasQuorumStakeThresholdSafetyMargin = 2/100`
- Combined threshold = `0.77`

**Attack:**
1. Adversary (Carol, stake = 500) sends one `PerasVote` for block `B_adv` in round `r` via the ObjectDiffusion mini-protocol.
2. `validatePerasVote` looks up Carol's stake: `vpvVoteStake = PerasVoteStake 500`.
3. `votesReachQuorum` computes `totalVoteStake = 500`.
4. `stakeAboveThreshold`: `500 >= 0.77` → **True** (absolute `500` vs relative `0.77`).
5. `updateCandidateVoteState` calls `forgePerasCert`, producing a `ValidatedPerasCert` for `B_adv` with boost `perasWeight = 15`.
6. The certificate is stored in `PerasVoteDB` and applied to chain selection: `B_adv` receives a weight boost of 15, causing honest nodes to prefer the adversary's chain.

The correct check should be `500/2000 = 0.25 >= 0.77` → **False** (quorum not reached).

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
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
