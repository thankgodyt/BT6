### Title
Peras Quorum Check Compares Accumulated Absolute Vote Stake Against a Relative Threshold Without Normalization, Enabling False Quorum Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares the accumulated `PerasVoteStake` (which will be absolute ledger-stake values once the real stake-distribution plumbing is wired in) directly against `perasQuorumStakeThreshold` (a relative `Rational` of `3/4`) without ever dividing by the total stake. The function's own TODO comment acknowledges the unit mismatch. The production diffusion handler in `NodeToNode.hs` currently passes `PerasVoteStakeDistr mempty` as a placeholder, which blocks all votes and masks the bug. When the placeholder is replaced with real ledger stake values, any single stake-pool operator whose absolute stake exceeds `0.77` (lovelace) — i.e., every operator — can trigger quorum alone, forge a certificate for an arbitrary block, and cause honest nodes to switch to a non-canonical chain via the Peras boost mechanism.

---

### Finding Description

**Root cause — `stakeAboveThreshold` (lines 162–173, `SupportsPeras.hs`)**

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake          -- accumulated vote stake
  quorumThreshold = unPerasQuorumStakeThreshold ...   -- 3/4 (relative)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ... -- 2/100 (relative)
```

The function's own documentation states the precondition it cannot enforce:

> "TODO: this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … Under the current implementation of 'PerasParams', this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [1](#0-0) 

`mkPerasParams` sets `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`, so the effective threshold is `0.77` — a relative fraction of total stake. [2](#0-1) 

**How `PerasVoteStake` is populated — `validatePerasVote` (lines 363–371, `SupportsPeras.hs`)**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The stake value is taken verbatim from `PerasVoteStakeDistr` with no normalization. The comment on `PerasVoteStake` itself admits there is no agreed-upon method for converting absolute ledger stake to a relative value:

> "NOTE: At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee." [3](#0-2) [4](#0-3) 

**Current masking — empty stake distribution in `NodeToNode.hs` (lines 400–408)**

```haskell
( makePerasVotePoolWriterFromChainDB
    systemTime
    -- TODO: when actual plumbing for Peras is ready, we will have to
    -- extract the committee selection data from the chainDB to pass
    -- it here, instead of relying on an empty the stake distribution.
    --
    -- Note that the empty stake distribution will cause all votes to
    -- be considered invalid.
    (pure (PerasVoteStakeDistr mempty))
    getChainDB
)
``` [5](#0-4) 

The placeholder `mempty` causes `lookupPerasVoteStake` to return `Nothing` for every voter, so `validatePerasVote` always returns `Left`, and `stakeAboveThreshold` is never reached. The TODO comment explicitly states this will be replaced with real ledger data.

**Quorum forging path — `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold` (lines 577–587, `Aggregation.hs`)**

```haskell
updateCandidateVoteState cfg vote oldState =
  let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
      voteList     = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
  in case votesReachQuorum cfg voteList of
       Just votesWithQuorum -> do
         cert <- forgePerasCert cfg votesWithQuorum
         pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
       Nothing ->
         pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
``` [6](#0-5) 

`votesReachQuorum` calls `stakeAboveThreshold` with the raw accumulated `PerasVoteStake`: [7](#0-6) 

---

### Impact Explanation

When the `PerasVoteStakeDistr` placeholder is replaced with real ledger data, the `PerasVoteStake` values will be absolute lovelace-denominated stake (e.g., `1_000_000_000_000` for a pool with 1 million ADA). `stakeAboveThreshold` will then evaluate:

```
1_000_000_000_000  >=  0.75 + 0.02   -- always True
```

A single vote from any stake pool operator immediately satisfies the quorum check, causing `forgePerasCert` to produce a `ValidatedPerasCert` for the voted block. That certificate is stored via `addPerasCertAsync`, which the `ChainDB.API` documents as: *"If this leads to a fork to be weightier than our current selection, this will trigger a fork switch."* [8](#0-7) 

The Peras boost weight is `perasWeight = 15` chain-lengths, so a single adversarially-forged certificate can make a minority fork appear heavier than the honest chain, causing honest nodes to roll back and adopt the adversary's chain. This is a **chain-selection safety failure** triggered by a single unprivileged peer who is a registered stake pool operator.

The inconsistency is structurally identical to the Olympus bug: in Olympus, frozen voted-votes (numerator) are compared against a dynamic total supply (denominator) that was never divided out; here, accumulated absolute vote stake (numerator) is compared against a relative threshold (denominator = total stake) that is never divided in.

---

### Likelihood Explanation

The bug is latent today because of the `mempty` placeholder, but the TODO comment in `NodeToNode.hs` explicitly marks it for replacement. Once real ledger stake data is plumbed in — a necessary step before Peras can function — the bug becomes immediately exploitable by any registered stake pool operator who can send a single vote message via the Peras vote diffusion mini-protocol. No key compromise, stake majority, or social engineering is required beyond normal stake pool participation.

---

### Recommendation

1. **Normalize before comparing.** `stakeAboveThreshold` must accept the total stake of the voting committee and divide the accumulated vote stake by it before comparing to the relative threshold:
   ```haskell
   stakeAboveThreshold params totalStake voteStake =
     (unPerasVoteStake voteStake / unPerasVoteStake totalStake)
       >= quorumThreshold + safetyMargin
   ```
   Alternatively, store only pre-normalized (relative) values in `PerasVoteStakeDistr` and enforce this invariant at the point where the distribution is constructed from ledger data.

2. **Enforce the unit invariant at construction time.** The `PerasVoteStakeDistr` builder (when real ledger plumbing is added) must normalize each voter's absolute stake by the total committee stake before inserting it, so that `stakeAboveThreshold` can safely assume relative units.

3. **Add a type-level or runtime guard.** Consider a `newtype RelativePerasVoteStake` distinct from absolute stake to make the unit mismatch a compile-time error rather than a runtime assumption.

---

### Proof of Concept

**Step 1 — Vote arrives via diffusion, validated with real stake distribution (future state):**

```
Peer  →  PerasVote { pvVoteRound = r, pvVoteBlock = adversarialBlock, pvVoteVoterId = poolId }
```

`processVotes` in `PerasVote.hs` calls `validatePerasVote mkPerasParams stakeDistr vote`. [9](#0-8) 

**Step 2 — `validatePerasVote` looks up absolute stake (e.g., `1_000_000_000_000`):** [4](#0-3) 

**Step 3 — `updateCandidateVoteState` calls `votesReachQuorum` with the single vote:** [10](#0-9) 

**Step 4 — `stakeAboveThreshold` evaluates `1_000_000_000_000 >= 0.77` → `True`:**

```haskell
stakeAboveThreshold params (PerasVoteStake 1_000_000_000_000)
-- stake = 1_000_000_000_000
-- quorumThreshold + safetyMargin = 0.75 + 0.02 = 0.77
-- 1_000_000_000_000 >= 0.77  →  True  ← FALSE QUORUM
``` [11](#0-10) 

**Step 5 — `forgePerasCert` produces a `ValidatedPerasCert` for `adversarialBlock`; `addPerasCertAsync` triggers a chain-selection fork switch to the adversary's chain.** [12](#0-11) [8](#0-7)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
```
