### Title
Peras Quorum Check Compares Unnormalized Accumulated Vote Stake Against a Relative Threshold — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares the accumulated `PerasVoteStake` (which is the raw sum of per-voter `VoteWeight` values, where persistent committee members contribute their **absolute** ledger stake in lovelace) against a **relative** (normalized, `Rational` in `[0,1]`) quorum threshold stored in `PerasParams`. The function itself carries an explicit TODO acknowledging this unit mismatch. Because absolute lovelace values are astronomically larger than any relative threshold (e.g., `0.75`), a single vote from any persistent committee member causes the quorum check to return `True`, allowing a certificate to be forged for an adversary-chosen block with a single crafted vote.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the core Peras quorum gate:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [1](#0-0) 

The function's own comment states:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `PerasVoteStake` fed into this function is the running sum of `vpvVoteStake` values accumulated in `ptvtTotalStake`:

```haskell
ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote)
``` [3](#0-2) 

Each vote's stake weight is produced by `implEligiblePartyVoteWeight`. For **persistent** committee members, this is the raw absolute `LedgerStake` (lovelace):

```haskell
WFALSPersistentMember _seatIndex (LedgerStake stake) ->
  VoteWeight stake
``` [4](#0-3) 

For non-persistent members the weight is normalized by `totalNonPersistentStake`, but persistent members are not normalized at all:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [5](#0-4) 

The quorum threshold is a `Rational` in `[0,1]` (e.g., `0.75`):

```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
``` [6](#0-5) 

The comparison `absolute_lovelace >= 0.75` is trivially `True` for any realistic stake value. The quorum check is called from `updateCandidateVoteState` via `votesReachQuorum`:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [7](#0-6) 

The same broken comparison is also used in `updateLoserVoteState` to detect the multiple-winner error condition, meaning the error path is also unreachable under normal operation.

---

### Impact Explanation

**High — Bypass of Peras certificate/vote quorum checks enabling unauthorized certificate acceptance.**

A single crafted vote from any persistent committee member causes `stakeAboveThreshold` to return `True` (absolute lovelace >> `0.75`), causing `forgePerasCert` to be called immediately. The resulting `ValidatedPerasCert` is stored in the vote DB and propagated. Because Peras certificates boost chain weight via `vpcCertBoost`, an adversary can force any honest node to prefer an adversary-chosen block by submitting a single vote for it, bypassing the intended `>3/4` quorum requirement entirely.

---

### Likelihood Explanation

**High.** The entry path is the standard Peras vote ingestion path (`implAddVote` → `updatePerasRoundVoteStates` → `updateCandidateVoteState` → `votesReachQuorum` → `stakeAboveThreshold`), reachable by any peer that can submit a valid Peras vote. No special privileges are required beyond being a persistent committee member (which is publicly deterministic from the stake distribution). The bug is self-documented in the source code as a known unit mismatch. [8](#0-7) 

---

### Recommendation

Normalize `PerasVoteStake` to a relative value before calling `stakeAboveThreshold`. Specifically, divide the accumulated absolute stake by the total active stake from the ledger's `PoolDistr` before the comparison, or change `stakeAboveThreshold` to accept the total stake and perform the normalization internally. Persistent member vote weight in `implEligiblePartyVoteWeight` should also be normalized by the total committee stake (persistent + non-persistent) to be consistent with the non-persistent member weight calculation.

---

### Proof of Concept

1. Observe that `perasQuorumStakeThreshold` is a `Rational` in `[0,1]` (e.g., `0.75`).
2. A persistent committee member with 1% of total Cardano stake holds approximately `4.5 × 10^14` lovelace.
3. `implEligiblePartyVoteWeight` returns `VoteWeight 4.5e14` for this member.
4. After one vote, `ptvtTotalStake = PerasVoteStake (4.5e14 :: Rational)`.
5. `stakeAboveThreshold` evaluates `4.5e14 >= 0.75 + safetyMargin` → `True`.
6. `forgePerasCert` is called, producing a certificate for the adversary's chosen block.
7. The certificate is stored and propagated, boosting the adversary's block in chain selection. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L413-417)
```haskell
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-432)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L94-98)
```haskell
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-211)
```haskell
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
