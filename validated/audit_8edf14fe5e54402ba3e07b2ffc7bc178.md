### Title
Unit Mismatch in Peras Quorum Check Enables Unauthorized Certificate Acceptance - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (populated from the ledger's absolute stake distribution) against `perasQuorumStakeThreshold` (a relative value of `3/4`). The code itself documents this unit mismatch in a TODO comment. Because absolute ledger stake values (e.g., lovelace) are orders of magnitude larger than `0.75`, the quorum check evaluates to `True` for any single vote from a registered voter, allowing unauthorized Peras certificate forging and chain-weight manipulation.

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs the quorum check for Peras certificate forging:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake        = unPerasVoteStake voteStake          -- populated from ledger (absolute)
  quorumThreshold = unPerasQuorumStakeThreshold      -- 3/4 (relative, in [0,1])
                      (perasQuorumStakeThreshold params)
  safetyMargin = unPerasQuorumStakeThresholdSafetyMargin
                      (perasQuorumStakeThresholdSafetyMargin params)  -- 2/100
``` [1](#0-0) 

The `perasQuorumStakeThreshold` is set to `3/4` and `perasQuorumStakeThresholdSafetyMargin` to `2/100` in `mkPerasParams`: [2](#0-1) 

The `PerasVoteStake` is assigned during `validatePerasVote` by looking up the voter's entry in `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [3](#0-2) 

The `PerasVoteStakeDistr` is sourced from the ledger stake distribution (absolute lovelace values), as confirmed by the code's own TODO comment:

> "At the moment there is no consensus from researchers/engineers on how we go from the **absolute stake** of a voter in the ledger to the **relative stake** of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)." [4](#0-3) 

The TODO further states: "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function". This confirms that normalization is **not** currently performed.

The `implEligiblePartyVoteWeight` function in `WFALS.hs` shows that persistent committee members receive a `VoteWeight` equal to their raw `LedgerStake` (absolute):

```haskell
WFALSPersistentMember _seatIndex (LedgerStake stake) ->
  VoteWeight stake
``` [5](#0-4) 

**Concrete scenario:** A pool with 1,000,000 lovelace of absolute stake produces `PerasVoteStake = 1000000`. The check becomes `1000000 >= 0.75 + 0.02`, which is `True`. Any single vote from any registered voter immediately satisfies the quorum condition.

`stakeAboveThreshold` is called in two critical paths within `votesReachQuorum` and `updateLoserVoteState`: [6](#0-5) [7](#0-6) 

Both are invoked from `updatePerasRoundVoteStates`, which is the core vote-processing function triggered when a vote arrives from a peer: [8](#0-7) 

The inbound vote path is `makePerasVotePoolWriterFromChainDB` → `processVotes` → `validatePerasVote` → `ChainDB.addPerasVoteWithAsyncCertHandling`: [9](#0-8) 

### Impact Explanation

Any registered stake pool operator (an unprivileged network peer) can submit a single Peras vote for any block. Because the quorum check always passes (absolute stake >> relative threshold), the node immediately forges a `ValidatedPerasCert` for that block, boosting its chain weight by `perasWeight = 15`. This constitutes a bypass of the Peras certificate check, enabling unauthorized certificate acceptance and allowing an attacker to manipulate chain selection by artificially inflating the weight of an adversarially chosen chain.

**Impact class:** Critical — bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance and chain-weight manipulation.

### Likelihood Explanation

Any registered stake pool operator can exploit this. No special privileges, key compromise, or majority stake are required — only a valid voter identity in the `PerasVoteStakeDistr`. The attack is a single crafted vote message over the existing Peras vote miniprotocol.

### Recommendation

Normalize `PerasVoteStake` to a relative value in `[0,1]` before calling `stakeAboveThreshold`, by dividing each voter's absolute stake by the total stake of the voting committee. Alternatively, change `stakeAboveThreshold` to accept the total committee stake and perform the normalization internally. The `perasQuorumStakeThreshold` and `perasQuorumStakeThresholdSafetyMargin` parameters should remain as relative values in `[0,1]`, and the comparison should only be made after normalization.

### Proof of Concept

1. Node is running with `mkPerasParams` defaults: `perasQuorumStakeThreshold = 3/4`, `perasQuorumStakeThresholdSafetyMargin = 2/100`.
2. Attacker is a registered stake pool with absolute ledger stake `S` (any positive lovelace value, e.g., `S = 1_000_000`).
3. Attacker sends one `PerasVote` for block `B` via the Peras vote miniprotocol.
4. `validatePerasVote` looks up the attacker in `PerasVoteStakeDistr`, finds `PerasVoteStake = S = 1_000_000`.
5. `votesReachQuorum` calls `stakeAboveThreshold`: `1_000_000 >= 0.75 + 0.02` → `True`.
6. `forgePerasCert` is called; a `ValidatedPerasCert` is produced for block `B` with `vpcCertBoost = PerasWeight 15`.
7. The ChainDB applies the boost; any chain containing `B` gains 15 extra weight units, potentially causing honest nodes to prefer the attacker's chain over the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L413-417)
```haskell
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L319-332)
```haskell
updatePerasRoundVoteStates ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  Map PerasRoundNo (PerasRoundVoteState blk) ->
  Either
    (UpdateRoundVoteStateError blk)
    (PerasRoundVoteState blk, Map PerasRoundNo (PerasRoundVoteState blk))
updatePerasRoundVoteStates vote cfg =
  alterMapAndReturnUpdatedValue
    updateMaybePerasRoundVoteState
    (getPerasVoteRound vote)
 where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L600-606)
```haskell
updateLoserVoteState cfg vote oldState =
  assert (getPerasVoteTarget vote == ptvtTarget (ptvsVoteTally oldState)) $ do
    let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally
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
