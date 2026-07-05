### Title
Peras Vote Stake Unit Mismatch Allows Single Voter to Forge Quorum Certificate and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in `SupportsPeras.hs` compares accumulated `PerasVoteStake` values against a relative quorum threshold (`3/4 + 2/100 = 0.77`) without any normalization step. The codebase explicitly acknowledges — via a TODO comment — that there is no consensus on how to convert absolute ledger stake to relative stake, and that the comparison only makes sense when both operands are in the same units. Because `PerasVoteStakeDistr` may be populated with absolute ledger stake values (e.g., lovelace), a single voter whose raw stake value exceeds `0.77` in those units can single-handedly satisfy the quorum check, causing a Peras certificate to be forged for any block they vote for. This certificate is then fed into chain selection, boosting the attacker's chosen block by `PerasWeight 15`, potentially displacing the honest chain.

---

### Finding Description

**Root cause — `stakeAboveThreshold` in `SupportsPeras.hs`:**

```haskell
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
``` [1](#0-0) 

The `PerasVoteStake` type is a bare `Rational` with no enforced normalization invariant:

```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee...
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
``` [2](#0-1) 

The quorum threshold is hardcoded as a relative value `3/4` with a safety margin of `2/100`: [3](#0-2) 

**Aggregation path — `votesReachQuorum` and `updateCandidateVoteState`:**

`votesReachQuorum` sums `vpvVoteStake` values from all `ValidatedPerasVote`s and calls `stakeAboveThreshold` directly:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) 

`updateCandidateVoteState` in `Vote/Aggregation.hs` calls `votesReachQuorum` after each vote is added to the tally, and immediately forges a certificate if quorum is declared reached:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [5](#0-4) 

**Validation stub — `validatePerasVote` performs no signature check:**

The production-path `validatePerasVote` implementation (the degenerate instance used for all blocks) only checks that the voter ID exists in the stake distribution; it ignores `_params` entirely and performs no cryptographic verification:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [6](#0-5) 

The stake lookup simply reads the raw value from `PerasVoteStakeDistr` without normalization: [7](#0-6) 

**Certificate processing triggers chain selection:**

Once a certificate is forged, `chainSelSync` in `ChainSel.hs` adds it to `PerasCertDB` and triggers chain selection for the boosted block: [8](#0-7) 

The boosted block receives a `PerasWeight` of 15 added to its `wsvWeightBoost`, which is summed into `wsvTotalWeight` used by `preferAnchoredCandidate` to select the chain: [9](#0-8) 

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute ledger stake values (e.g., lovelace amounts such as `1_000_000`), then `unPerasVoteStake = 1000000 >> 0.77`. A single vote from any voter with non-trivial absolute stake immediately satisfies `stakeAboveThreshold`, causing a certificate to be forged for the attacker's chosen block. That certificate is processed by `chainSelSync`, which adds a `PerasWeight 15` boost to the attacker's block. Chain selection then uses `wsvTotalWeight = blockNo + weightBoost` to compare chains; with a boost of 15, the attacker's chain is preferred over an honest chain that is up to 15 blocks longer. This constitutes a **chain selection bug** that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

**Medium-High.** The entry path is the Peras vote diffusion mini-protocol, reachable by any peer. The `validatePerasVote` stub performs no signature verification, so an attacker does not need to compromise any key — they only need to know a valid voter ID from the stake distribution (which is public ledger state). The unit mismatch is explicitly documented as unresolved. The attack requires only one crafted vote message per round.

---

### Recommendation

1. **Normalize `PerasVoteStake` before comparison.** Either normalize the values when populating `PerasVoteStakeDistr` (divide each voter's absolute stake by the total stake), or modify `stakeAboveThreshold` to accept the total stake and perform normalization internally. Enforce the invariant at the type level (e.g., a `NormalizedPerasVoteStake` newtype).

2. **Implement cryptographic vote validation.** The `validatePerasVote` implementation must verify the vote signature and, for non-persistent members, the VRF eligibility proof, before accepting a vote. The current stub that ignores `_params` and performs no cryptographic check must not be used in any production code path.

3. **Add a per-voter deduplication check at the quorum gate.** `votesReachQuorum` should verify that no single voter's stake alone exceeds the quorum threshold, analogous to the oracle recommendation to detect when a single provider dominates the VWAP.

---

### Proof of Concept

**Private testnet sequence:**

1. Start a node with Peras enabled. Observe the `PerasVoteStakeDistr` populated from the ledger (absolute lovelace values, e.g., voter `V` has stake `1_000_000`).

2. Craft a `PerasVote` message claiming voter ID `V`, targeting an attacker-controlled block `B_adv` in round `R`:
   ```
   PerasVote { pvVoteRound = R, pvVoteBlock = B_adv, pvVoteVoterId = V }
   ```

3. Send the vote via the object diffusion mini-protocol. `processVotes` calls `validatePerasVote`, which looks up `V` in the distribution and returns `ValidatedPerasVote { vpvVoteStake = PerasVoteStake (1000000 % 1) }`.

4. `updateCandidateVoteState` calls `votesReachQuorum`. `stakeAboveThreshold` evaluates `1000000 >= 0.75 + 0.02` → `True`. A certificate is immediately forged for `B_adv`.

5. `chainSelSync` processes the certificate, adds `PerasWeight 15` to `B_adv`'s weight snapshot. Chain selection now prefers any chain containing `B_adv` over an honest chain up to 15 blocks longer.

6. The node switches to the attacker's chain, demonstrating a chain selection manipulation by a single unprivileged peer with a single crafted vote message.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L41-60)
```haskell
data WeightedSelectView proto = WeightedSelectView
  { wsvBlockNo :: !BlockNo
  -- ^ The 'BlockNo' at the tip of a fragment.
  , wsvWeightBoost :: !PerasWeight
  -- ^ The weight boost of a fragment (w.r.t. a particular anchor).
  , wsvTiebreaker :: TiebreakerView proto
  -- ^ Lazy because it is only needed when 'wsvTotalWeight' is inconclusive.
  }

deriving stock instance Show (TiebreakerView proto) => Show (WeightedSelectView proto)
deriving stock instance Eq (TiebreakerView proto) => Eq (WeightedSelectView proto)

-- TODO: More type safety to prevent people from accidentally comparing
-- 'WeightedSelectView's obtained from fragments with different anchors?
-- Something ST-trick like?

-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
```
