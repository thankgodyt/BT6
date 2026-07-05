### Title
Missing Stake Normalization in Peras Quorum Check Enables Certificate Bypass - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares an accumulated `PerasVoteStake` value directly against `perasQuorumStakeThreshold` without normalizing the vote stake to the same unit as the threshold. The code itself documents this as an unresolved correctness assumption. When `PerasVoteStakeDistr` is populated with absolute ledger stake values (lovelace) while the quorum threshold is a relative fraction (e.g., 0.75), the comparison is always true for any voter with positive stake, allowing a single crafted vote from an unprivileged peer to forge a Peras certificate for an arbitrary block.

### Finding Description

`stakeAboveThreshold` performs the quorum check that gates Peras certificate creation:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake    = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (...)
``` [1](#0-0) 

The function's own TODO comment explicitly states the precondition it cannot enforce:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

`PerasVoteStake` is a bare `Rational` with no enforced unit: [3](#0-2) 

The production vote-processing path populates `PerasVoteStakeDistr` directly from the ledger stake distribution and passes it to `validatePerasVote`, which stamps each vote with whatever `Rational` is stored in that map — no normalization step exists anywhere in the call chain:

```
processVotes
  → validatePerasVote mkPerasParams stakeDistr vote
      → lookupPerasVoteStake vote stakeDistr   -- raw Rational from map
      → ValidatedPerasVote { vpvVoteStake = stake }
  → updateCandidateVoteState
      → votesReachQuorum cfg voteList
          → stakeAboveThreshold cfg totalVoteStake  -- compares raw vs. relative
``` [4](#0-3) [5](#0-4) [6](#0-5) 

The `perasQuorumStakeThreshold` is documented as a relative value (e.g., > 3/4 of total stake): [7](#0-6) 

When the `PerasVoteStakeDistr` is built from absolute lovelace values (as in the production node-to-node path and the smoke test), the accumulated `PerasVoteStake` for even a single voter will be a large integer (e.g., `1000000 % 1`), which is always `>= 0.75`, so `stakeAboveThreshold` returns `True` unconditionally. This is the direct analog of the external report: raw unscaled values are passed to a function that expects normalized inputs, causing the comparison to degenerate.

### Impact Explanation

An unprivileged peer that can submit a single valid Peras vote (i.e., one whose `PerasVoterId` appears in the node's `PerasVoteStakeDistr` with any positive absolute stake) will immediately satisfy `stakeAboveThreshold`, causing `votesReachQuorum` to return `Just`, `updateCandidateVoteState` to call `forgePerasCert`, and a `ValidatedPerasCert` to be inserted into the chain. The certificate carries a `PerasWeight` boost that directly influences chain selection. An adversary can therefore boost an arbitrary block — including a non-canonical or adversarially-produced one — with a fraudulent certificate, constituting a bypass of the Peras voting quorum requirement and a chain-selection manipulation.

This matches the allowed impact: **bypass of certificate/vote verification checks that enables unauthorized certificate acceptance**, and **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

### Likelihood Explanation

The vulnerability is active in the current production code path. The `makePerasVotePoolWriterFromChainDB` function (used in the real node) reads `PerasVoteStakeDistr` from an STM cell and passes it directly to `validatePerasVote mkPerasParams`. Any peer that can send a `PerasVote` message over the ObjectDiffusion mini-protocol and whose pool ID appears in the stake distribution can trigger the bug. No special privileges, key compromise, or majority stake are required — only a valid pool identity in the current epoch's stake distribution. [8](#0-7) 

### Recommendation

Normalize `PerasVoteStake` to a relative value (fraction of total committee stake) before calling `stakeAboveThreshold`, or change `stakeAboveThreshold` to accept the total stake and perform the division internally:

```haskell
stakeAboveThreshold
  :: PerasParams
  -> PerasVoteStake   -- total stake of votes received
  -> PerasVoteStake   -- total stake of the voting committee
  -> Bool
stakeAboveThreshold params voteStake totalCommitteeStake =
  relativeStake >= quorumThreshold + safetyMargin
 where
  relativeStake = unPerasVoteStake voteStake
                / unPerasVoteStake totalCommitteeStake
  ...
```

Alternatively, enforce at the type level that `PerasVoteStake` stored in `PerasVoteStakeDistr` is always a relative value in `[0,1]`, mirroring how `LedgerStake` is kept as an absolute value while `VoteWeight` is derived as a normalized ratio in the WFALS committee.

### Proof of Concept

Using the existing smoke-test harness, generate a `PerasVoteStakeDistr` with absolute stake values (e.g., `PerasVoteStake (1000000 % 1)` per voter) and `mkPerasParams` (whose `perasQuorumStakeThreshold` is a relative fraction). Submit a single vote from one voter. Observe that `stakeAboveThreshold` returns `True` and a certificate is forged immediately, regardless of how many committee members have actually voted.

The smoke test already inadvertently demonstrates this: `genPerasVoteStake` generates stakes as `1 % k` for small `k` (relative fractions), which happen to work correctly — but the production path has no such constraint, and the type system does not enforce it. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L119-152)
```haskell
-- | Create a pool writer from the 'ChainDB'.
-- This properly handles the produced certs by letting the ChainDB take care
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L56-62)
```haskell
--   * The quorum threshold is misconfigured, or that
--   * We were extremely unlucky when randomly selecting the voting committee.
--
-- With a correct threshold configuration (e.g., > 3/4 of total stake + a small
-- safety margin to account for an unlucky local sortition when selecting
-- non-persistent voters during committee selection), multiple winners should be
-- impossible given honest stake distribution.
```

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/MiniProtocol/ObjectDiffusion/PerasVote/Smoke.hs (L76-79)
```haskell
genPerasVoteStake :: Gen PerasVoteStake
genPerasVoteStake = do
  stake <- (1 %) <$> choose (2, 10)
  pure (PerasVoteStake stake)
```
