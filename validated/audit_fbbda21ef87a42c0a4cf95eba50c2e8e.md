### Title
Peras Quorum Check Bypassed by Missing Vote-Stake Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares the raw sum of individual `PerasVoteStake` values against a relative quorum threshold without normalizing the vote stakes to the same unit. Because the `PerasVoteStakeDistr` is populated from the ledger's absolute stake values while the quorum threshold is a relative `Rational` (e.g. `3/4`), the comparison is dimensionally inconsistent. An unprivileged peer can send a single `PerasVote` whose voter holds any non-trivial absolute stake, immediately satisfying the quorum check and causing the node to forge and accept a Peras certificate for an arbitrary block, boosting that block's weight in chain selection.

---

### Finding Description

`PerasVoteStake` is defined as a bare `Rational` with an explicit design note acknowledging the unresolved normalization problem:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [1](#0-0) 

`stakeAboveThreshold` directly compares the accumulated `PerasVoteStake` sum against the relative `perasQuorumStakeThreshold` without any normalization step:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

The function's own TODO comment acknowledges the defect:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

`validatePerasVote` passes the raw ledger stake directly into the validated vote without normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [3](#0-2) 

`votesReachQuorum` then sums these raw stakes and calls `stakeAboveThreshold`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) 

`updateCandidateVoteState` in the aggregation module calls `votesReachQuorum` and, on success, immediately forges a certificate: [5](#0-4) 

The vote pool writer, reachable from the network layer, reads the `PerasVoteStakeDistr` from an STM action and passes it directly to `validatePerasVote`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [6](#0-5) 

---

### Impact Explanation

When `PerasVoteStakeDistr` is populated with absolute ledger stake values (e.g. lovelace), a single voter holding even 1 lovelace produces `PerasVoteStake = 1 % 1`. The quorum threshold is a relative `Rational` such as `3 % 4`. The comparison `1 >= 3/4` is immediately true, so a single vote from any voter in the distribution forges a certificate for an arbitrary block. That certificate is inserted into the `PerasWeightSnapshot` and boosts the target block's weight in chain selection:

```haskell
wsvTotalWeight wsv = PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [7](#0-6) 

An honest node will then prefer the adversarially boosted chain over the canonical chain, constituting a chain-selection safety failure.

---

### Likelihood Explanation

The defect is reachable via the standard Peras vote object-diffusion mini-protocol, which is open to any connected peer. No key compromise, stake majority, or operator action is required. The attacker only needs to be a voter present in the current epoch's `PerasVoteStakeDistr` (i.e. any registered stake pool). The TODO comment and the `PerasVoteStake` design note confirm the normalization step is absent in the current implementation, not merely deferred behind a flag.

---

### Recommendation

1. **Normalize at validation time**: `validatePerasVote` must divide the voter's absolute ledger stake by the total committee stake before storing it as `vpvVoteStake`, so that `PerasVoteStake` is always a value in `[0, 1]`.
2. **Enforce units at the type level**: Introduce a `NormalizedStake` newtype distinct from `AbsoluteStake` so the compiler rejects unnormalized values being passed to `stakeAboveThreshold`.
3. **Pass total stake into `stakeAboveThreshold`**: As the TODO suggests, accept the full `PerasVoteStakeDistr` and perform normalization internally, eliminating the caller's responsibility.

---

### Proof of Concept

**Setup**: `PerasVoteStakeDistr` contains `{ poolA → PerasVoteStake (1_000_000 % 1) }` (absolute lovelace). `perasQuorumStakeThreshold = 3 % 4`.

1. Adversary peer sends one `PerasVote` for block `B` with `pvVoteVoterId = poolA`.
2. `validatePerasVote` looks up `poolA` → `PerasVoteStake (1_000_000 % 1)`, stores it in `ValidatedPerasVote`.
3. `updateCandidateVoteState` calls `votesReachQuorum` → `totalVoteStake = 1_000_000 % 1`.
4. `stakeAboveThreshold`: `1_000_000 >= 3/4` → `True`. Quorum declared.
5. `forgePerasCert` produces a `ValidatedPerasCert` for block `B` with boost `perasWeight`.
6. `addPerasCertAsync` inserts the cert into `PerasWeightSnapshot`.
7. `chainSelectionForBlock` reads the snapshot; block `B`'s `wsvTotalWeight` is inflated by the boost.
8. Honest node switches to the adversary's chain containing `B`, even if it is not the canonical chain. [2](#0-1) [5](#0-4) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-686)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

  -- The current chain we're working with here is not longer than @k@ blocks
  -- (see 'getCurrentChain' and 'cdbChain'), which is easier to reason about
  -- when doing chain selection, etc.
  assert (fromIntegral (AF.length curChain) <= unNonZero k) pure ()

  let
    immBlockNo :: WithOrigin BlockNo
    immBlockNo = AF.anchorBlockNo curChain

  if
    -- The chain might have grown since we added the block such that the
    -- block is older than the immutable tip.
    | olderThanImmTip hdr immBlockNo -> do
        traceWith addBlockTracer $ IgnoreBlockOlderThanImmTip p

    -- The block is invalid
    | Just (InvalidBlockInfo reason _) <- Map.lookup (headerHash hdr) invalid -> do
        traceWith addBlockTracer $ IgnoreInvalidBlock p reason

        -- We wouldn't know the block is invalid if its prefix was invalid,
        -- hence 'InvalidBlockPunishment.BlockItself'.
        InvalidBlockPunishment.enact
          punish
          InvalidBlockPunishment.BlockItself

    -- Try to select a chain involving the block.
    | otherwise -> do
        -- Construct all 'ChainDiff's involving the block.
        chainDiffs <-
          constructPreferableCandidates
            cdb
            weights
            curChain
            (Map.singleton (headerHash hdr) hdr)
            (headerRealPoint hdr)

        let traceNoChange = traceWith addBlockTracer $ StoreButDontChange p

            chainSelEnv = mkChainSelEnv cdb blockCache weights curChain (Just (p, punish))

        case NE.nonEmpty chainDiffs of
          Just chainDiffs' -> do
            -- Find the best valid candidate and, if valid, perform a
            -- switch. Log if none were found.
            flip whenNothing traceNoChange
              =<< chainSelection
                chainSelEnv
                chainDiffs'
                (switchTo cdb weights (Just p))
          -- No candidate better than our chain.
          Nothing -> traceNoChange
```
