### Title
Peras Quorum Check Bypassed Due to Missing Vote Stake Normalization — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares accumulated `PerasVoteStake` values against a relative quorum threshold (`3/4 + 2/100 = 0.77`) without enforcing that the vote stake values are normalized. The function's own inline comment acknowledges this assumption is unverified. If the `PerasVoteStakeDistr` supplied at runtime contains absolute ledger stake values (the natural representation from the Cardano ledger), any registered stake pool with any positive stake can trigger quorum with a single vote, forging a Peras certificate and causing unauthorized chain boosting.

---

### Finding Description

`stakeAboveThreshold` is defined as:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The comment immediately above this function explicitly states:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The quorum threshold in `mkPerasParams` is `3/4` with a safety margin of `2/100`, giving a combined threshold of `0.77`: [3](#0-2) 

The callers of `stakeAboveThreshold` — `votesReachQuorum` and `updateCandidateVoteState` — sum raw `vpvVoteStake` values and pass them directly without normalization:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) [5](#0-4) 

The `vpvVoteStake` values originate from `validatePerasVote`, which assigns them directly from `PerasVoteStakeDistr` with no normalization step:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [6](#0-5) 

The `PerasVoteStakeDistr` is a `Map PerasVoterId PerasVoteStake` where `PerasVoteStake` is an opaque `Rational`. The comment on `PerasVoteStake` itself acknowledges the unresolved unit question:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [7](#0-6) 

The stake distribution is read at vote-validation time from an STM action supplied by the node:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [8](#0-7) 

If `getStakeDistrSTM` yields absolute ledger stake values (e.g., lovelace amounts), a pool with even 1 lovelace of stake has `PerasVoteStake (1 % 1) = 1.0`, which satisfies `1.0 >= 0.77` trivially. A single vote from that pool causes `votesReachQuorum` to return `Just`, `forgePerasCert` to produce a `ValidatedPerasCert`, and `addPerasCertAsync` to trigger chain selection for the attacker's chosen block.

This is structurally identical to the external report: two checks exist (voter is in the distribution; total stake ≥ threshold), but the second check is vacuously satisfied because the "current threshold" (a relative `Rational`) is compared against a value that was never normalized to the same unit — exactly as `safe.getThreshold()` could be reduced below `minThreshold` while both existing checks still passed.

---

### Impact Explanation

**Critical.** Any registered stake pool — an unprivileged network peer — can forge a Peras certificate for an arbitrary block by sending a single vote. The forged certificate is accepted by `processCerts` → `PerasCertDB.addCert` → `chainSelSync` → `chainSelectionForBlock`, causing the honest node to boost and potentially switch to a non-canonical chain. This breaks Peras chain-selection safety: the boosted block gains `perasWeight = 15` extra weight, which can override the honest longest-chain preference.

---

### Likelihood Explanation

**High.** The entry path is the public vote diffusion mini-protocol, reachable by any peer. The precondition is only that the attacker controls a registered stake pool (a `PerasVoterId` present in the stake distribution). The comment in the source code explicitly flags the normalization gap as unresolved, and `mkPerasParams` is used as the hardcoded config in both production pool writers, meaning the threshold is always `0.77` regardless of actual network stake.

---

### Recommendation

Normalize `PerasVoteStake` values before they reach `stakeAboveThreshold`. Concretely, either:

1. In `validatePerasVote`, divide the looked-up stake by the sum of all values in `PerasVoteStakeDistr` to produce a relative weight in `[0,1]`.
2. Change `stakeAboveThreshold` to accept the full `PerasVoteStakeDistr` and perform normalization internally, removing the undocumented caller precondition.

Additionally, add a type-level or runtime invariant asserting that the sum of all `PerasVoteStake` values in a `PerasVoteStakeDistr` equals `1` before any quorum check is performed.

---

### Proof of Concept

1. Operate a registered stake pool with any positive ledger stake (e.g., 1 lovelace).
2. Send a single `PerasVote` for a target block `B` via the vote diffusion mini-protocol.
3. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; the voter is found in `sd`, so `vpvVoteStake` is set to the absolute ledger stake value (e.g., `1000000 % 1`).
4. The vote is added to `PerasVoteDB`; `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum` is called.
5. `stakeAboveThreshold mkPerasParams (PerasVoteStake (1000000 % 1))` evaluates `1000000 >= 0.77` → `True`.
6. `forgePerasCert` produces a `ValidatedPerasCert` boosting block `B` with weight 15.
7. `addPerasCertAsync` enqueues the cert; `chainSelSync` runs `chainSelectionForBlock` for `B`, causing the honest node to prefer the attacker's chain. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L571-587)
```haskell
  PerasCfg blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteState blk 'Candidate ->
  Either
    (PerasForgeErr blk)
    (PerasVoteStateCandidateOrWinner blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```
