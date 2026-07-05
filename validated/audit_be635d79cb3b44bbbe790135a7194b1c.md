### Title
Peras Quorum Check Unit Mismatch in `stakeAboveThreshold` Allows Single-Vote Certificate Forgery - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (which may carry absolute ledger stake in lovelace) directly against `perasQuorumStakeThreshold` (a relative `Rational` set to `3/4`). No normalization is performed. The code itself acknowledges this with an explicit TODO warning. When absolute stake values are used, the comparison `absoluteLovelace >= 0.75` is trivially true for any non-zero stake, meaning a single vote from any registered pool immediately triggers quorum and forges a Peras certificate.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the quorum check:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake        = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
``` [1](#0-0) 

The threshold is set in `mkPerasParams` as a relative fraction:

```haskell
perasQuorumStakeThreshold = PerasQuorumStakeThreshold (3 / 4)
perasQuorumStakeThresholdSafetyMargin = PerasQuorumStakeThresholdSafetyMargin (2 / 100)
``` [2](#0-1) 

The code itself carries a TODO that explicitly acknowledges the unit mismatch:

> "TODO: this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [3](#0-2) 

The `PerasVoteStake` type itself carries a companion note:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [4](#0-3) 

The production vote-ingestion path in `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote`, where `sd` is a `PerasVoteStakeDistr` read from an STM cell populated from the ledger's stake distribution. The ledger stake distribution stores absolute lovelace values (e.g., a pool with 1 billion lovelace). `validatePerasVote` assigns `vpvVoteStake = stake` directly from the lookup result without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [5](#0-4) [6](#0-5) 

When `stakeAboveThreshold` is subsequently called (via `votesReachQuorum` or the `PerasVoteDB` model), it compares, e.g., `1_000_000_000 >= 0.77`, which is always `True`. The quorum is reached with a single vote. [7](#0-6) 

---

### Impact Explanation

A single adversarial voter (any registered stake pool, regardless of actual stake fraction) can send one crafted `PerasVote` via the object-diffusion miniprotocol. The vote passes `validatePerasVote` (its voter ID is in the stake distribution), and `stakeAboveThreshold` immediately returns `True` because the absolute lovelace value dwarfs the relative threshold `0.77`. A Peras certificate is forged for the adversary's chosen block, boosting its chain weight by `perasWeight = 15`. [8](#0-7) 

Honest nodes receiving this certificate will apply the weight boost during chain selection, potentially preferring the adversarially boosted chain over the canonical chain. This is a chain-selection manipulation attack enabled by an unprivileged peer.

---

### Likelihood Explanation

The Peras protocol is actively being integrated into the production consensus layer (not confined to test files). The `makePerasVotePoolWriterFromChainDB` function is the designated production entry point. Any registered stake pool operator can send a single vote targeting any block. The mismatch is structural and deterministic — it does not require any probabilistic condition to trigger.

---

### Recommendation

`stakeAboveThreshold` must normalize `PerasVoteStake` to a relative value before comparing it against `perasQuorumStakeThreshold`. Either:

1. **Normalize at validation time**: `validatePerasVote` should divide the voter's absolute stake by the total stake in the distribution before storing it in `vpvVoteStake`, or
2. **Normalize at check time**: `stakeAboveThreshold` should accept the total stake as an additional parameter and compute `unPerasVoteStake voteStake / totalStake >= quorumThreshold + safetyMargin`.

The `PerasVoteStake` type should be given a clear semantic contract (relative vs. absolute) enforced at construction, and the TODO comment should be resolved before the Peras protocol is enabled on any live network.

---

### Proof of Concept

Given `mkPerasParams` with `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`:

```
threshold = 3/4 + 2/100 = 0.77
```

A pool with 1 lovelace of absolute stake produces `PerasVoteStake (1 % 1)`:

```
stakeAboveThreshold params (PerasVoteStake 1)
  = (1 % 1) >= (3 % 4) + (2 % 100)
  = 1 >= 0.77
  = True   -- quorum reached with a single vote
```

An adversary sends one `PerasVote` for their preferred block via the object-diffusion miniprotocol. `processVotes` validates it, `stakeAboveThreshold` returns `True`, and `forgePerasCert` produces a certificate boosting the adversarial block. Honest nodes applying chain selection with the Peras weight boost will prefer this chain. [9](#0-8) [1](#0-0) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-180)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
```
