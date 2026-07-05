### Title
Single Invalid Peras Vote/Certificate in Batch Silently Discards All Valid Items, Suppressing Weight Boosts and Weakening Chain Selection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`, `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

`processVotes` and `processCerts` implement an all-or-nothing batch policy: if any single item in an inbound batch fails validation, the entire batch is thrown away and a disconnect exception is raised. An unprivileged peer can exploit this by injecting one crafted invalid vote or certificate alongside legitimate ones, causing all valid items to be silently dropped. Because Peras votes accumulate toward quorum and certificates carry the weight boosts that drive chain selection, suppressing them lets an adversary prevent the canonical chain from receiving its Peras weight advantage, materially weakening chain selection.

---

### Finding Description

`processVotes` in `PerasVote.hs` and `processCerts` in `PerasCert.hs` share the same structural flaw. After running `partitionEithers` over the validation results, the code discards the valid items (the second element of the pair) whenever the error list is non-empty:

```haskell
-- PerasVote.hs lines 184-201
case partitionEithers validationResults of
  ([], validatedVotes) ->
    mapM_ (addVote . WithArrivalTime now) validatedVotes
  -- valid votes in the second element are silently dropped:
  (errs, _) ->
    throw (PerasVoteValidationError errs)
``` [1](#0-0) 

The identical pattern appears in `processCerts`:

```haskell
-- PerasCert.hs lines 168-185
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

The code comments even acknowledge the design choice explicitly: *"Some certs are invalid => reject the whole batch"*. The `throw` (from `GHC.Exception`, not `throwIO`) propagates as a pure exception caught by the `withPeer` bracket in `ouroboros-network`, disconnecting the sender — but the valid items are already gone.

The vote validation path that can be triggered by a crafted vote is `validatePerasVote`, which returns `Left PerasValidationErr` when `lookupPerasVoteStake` finds no entry for the voter ID in the stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr = Right ...
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

Any peer can craft a vote with a voter ID absent from the current stake distribution and bundle it with legitimate votes from real committee members.

---

### Impact Explanation

Peras certificates carry a `vpcCertBoost :: PerasWeight` that is added to a chain fragment's total weight during chain selection. The `WeightedSelectView` compares chains by `wsvTotalWeight`, which is `BlockNo + wsvWeightBoost`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

`preferCandidate` switches to a candidate chain when its `wsvTotalWeight` exceeds the current chain's:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch ...
``` [5](#0-4) 

If an adversary suppresses the votes needed to reach quorum for a round, no certificate is forged, the canonical chain's block receives no boost, and a competing chain with a higher raw block number (or its own boost) can be preferred. This is a chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions.

The `addPerasCertAsync` path in `ChainDB` explicitly triggers chain re-selection when a certificate arrives:

```haskell
-- ChainSel.hs: chainSelSync for ChainSelAddPerasCert
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

Suppressing the certificate therefore directly suppresses the chain-selection re-evaluation that would have favoured the canonical chain.

---

### Likelihood Explanation

The attack requires only a network connection to the target node. The adversary does not need stake, keys, or any privileged position. They need only:

1. Know (or guess) any voter ID that is **not** in the current stake distribution — trivially achievable by using a random or zeroed key hash.
2. Observe or intercept a batch of legitimate votes being relayed (or simply wait for a round where votes are being diffused).
3. Inject one crafted invalid vote into the batch before forwarding it.

The `ObjectPoolWriter.opwAddObjects` is called directly from the mini-protocol handler for each received batch. The blast radius scales linearly with the number of valid votes in the batch: one invalid entry drops all of them.

---

### Recommendation

Apply valid items before (or instead of) aborting on invalid ones. The peer should still be disconnected for sending invalid data, but valid items must not be discarded:

```haskell
-- processVotes / processCerts fix
case partitionEithers validationResults of
  ([], validatedVotes) ->
    mapM_ (addVote . WithArrivalTime now) validatedVotes
  (errs, validatedVotes) -> do
    -- Persist the valid items first
    mapM_ (addVote . WithArrivalTime now) validatedVotes
    -- Then disconnect the misbehaving peer
    throw (PerasVoteValidationError errs)
```

The same change applies symmetrically to `processCerts`.

---

### Proof of Concept

**Setup:** Honest node N is collecting votes for Peras round R. Committee members A, B, C have each sent their votes to a relay peer P. Quorum requires 3 votes.

1. Adversary connects to N before peer P delivers the batch.
2. Adversary sends a single batch: `[voteA, voteB, voteC, craftedInvalidVote]` where `craftedInvalidVote` has a voter ID not in the stake distribution.
3. `processVotes` runs `mapM validateVote` over all four votes inside a single `atomically` block.
4. `partitionEithers` yields `([PerasValidationErr], [validatedA, validatedB, validatedC])`.
5. The `(errs, _)` branch matches; `validatedA`, `validatedB`, `validatedC` are discarded.
6. `throw (PerasVoteValidationError [PerasValidationErr])` fires; adversary is disconnected.
7. Votes A, B, C are never added to the `PerasVoteDB`; quorum is not reached; no certificate is forged for round R.
8. The block that would have been boosted by the round-R certificate receives `wsvWeightBoost = 0`.
9. A competing chain with one additional block (block number advantage) now satisfies `wsvTotalWeight cand > wsvTotalWeight ours`, and `chainSelection` switches to it. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
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
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
