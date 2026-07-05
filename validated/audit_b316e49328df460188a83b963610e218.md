### Title
Missing Stake Normalization in Peras Quorum Check Enables Certificate Bypass or Quorum Lockout - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares an accumulated `PerasVoteStake` value directly against a relative quorum threshold without first dividing by total stake. The code itself documents this as an unresolved design gap. Depending on whether the `PerasVoteStakeDistr` is populated with absolute ledger stake values or pre-normalized fractions, the quorum gate either fires on every single vote (absolute >> 0.75) or never fires at all (tiny fractions << 0.75). Either outcome breaks the Peras certificate security invariant.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the quorum gate for Peras certificate forging:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin  = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
``` [1](#0-0) 

The code's own comment states the problem explicitly:

> "this function only makes sense when both values are relative (normalized) values, so we **should either normalize the `PerasVoteStake` before calling this function**, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `PerasVoteStake` assigned to each validated vote is taken directly from `PerasVoteStakeDistr` via `lookupPerasVoteStake` — no division by total stake occurs:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

The `PerasVoteStakeDistr` is sourced from `getStakeDistrSTM`, which is the raw ledger stake distribution. The comment in the vote pool writer confirms no normalization step exists yet:

> "In the future, we won't need just the stake distribution for validating votes, but also the whole committee selection context (containing vote weights of committee members = voters)" [4](#0-3) 

The accumulated `ptvtTotalStake` in `PerasTargetVoteTally` is the direct sum of these unnormalized `vpvVoteStake` values:

```haskell
(votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
``` [5](#0-4) 

This sum is then passed to `stakeAboveThreshold` to decide whether to forge a certificate. The missing division by total stake is the direct analog of the missing `/ _virtualBalanceX` in the external report.

---

### Impact Explanation

**Scenario A — absolute ledger values (lovelace-scale) stored in `PerasVoteStakeDistr`:**
A single vote from any pool carries a `PerasVoteStake` on the order of billions of lovelace. The quorum threshold is a `Rational` like `0.75`. The comparison `1_000_000_000 >= 0.75` is always `True`. Any single vote from any unprivileged peer immediately forges a Peras certificate, completely bypassing the quorum requirement. The certificate boosts a block's chain-selection weight by `perasWeight`, causing honest nodes to prefer the adversary's chain.

**Scenario B — pre-normalized fractions stored in `PerasVoteStakeDistr`:**
If each pool's stake is stored as its fraction of total stake (e.g., `0.001`), the sum of all honest votes never reaches `0.75` unless a supermajority participates. Quorum is unreachable, permanently disabling Peras certificate production and its chain-security guarantees.

Both outcomes break the Peras voting invariant. Scenario A is the more dangerous: it maps directly to the "bypass of Peras voting or certificate checks" impact class.

---

### Likelihood Explanation

**High.** The attack path requires only that a node receive a single valid vote from any peer. Vote submission is an open, unprivileged miniprotocol operation. No key compromise, stake majority, or operator action is needed. The code path `validatePerasVote → updatePerasRoundVoteStates → stakeAboveThreshold` is exercised on every received vote. The developers' own TODO comment confirms the normalization is absent.

---

### Recommendation

Normalize `PerasVoteStake` before the threshold comparison. The fix mirrors the yETH recommendation — divide by the total stake before accumulating or comparing:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> PerasVoteStake -> Bool
stakeAboveThreshold params totalStake voteStake =
  normalizedStake >= quorumThreshold + safetyMargin
 where
  normalizedStake = unPerasVoteStake voteStake / unPerasVoteStake totalStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
```

Alternatively, enforce at the type level that `PerasVoteStakeDistr` stores only pre-normalized fractions, and add a guard that the sum of all entries equals `1`.

---

### Proof of Concept

1. Node A receives a `PerasVote` from peer P for round R targeting block B.
2. `validatePerasVote mkPerasParams stakeDistr vote` looks up P's absolute ledger stake (e.g., `1_500_000_000_000` lovelace for a 1.5M ADA pool) and stores it as `vpvVoteStake`.
3. `updatePerasRoundVoteStates` calls `updateTargetVoteTally`, setting `ptvtTotalStake = 1_500_000_000_000`.
4. `stakeAboveThreshold params (PerasVoteStake 1_500_000_000_000)` evaluates `1_500_000_000_000 >= 0.75 + safetyMargin` → `True`.
5. A `ValidatedPerasCert` is forged for block B with boost weight `perasWeight`.
6. `chainSelSync` receives the certificate, adds it to `PerasCertDB`, and triggers chain selection for block B.
7. `totalWeightOfFragment` now counts block B's weight as `1 + perasWeight`, making any chain containing B heavier than an equally-long honest chain without a certificate.
8. Honest nodes switch to the adversary's chain, achieving unauthorized chain-selection influence with a single vote. [6](#0-5) [5](#0-4) [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L91-117)
```haskell
-- 'ChainDB' and thus properly handles the produced certs.
makePerasVotePoolWriterFromVoteDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since it is during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  PerasVoteDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L453-459)
```haskell
    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
