### Title
Peras `validatePerasVote` and `validatePerasCert` Stubs Accept Any Inbound Vote/Certificate Without Cryptographic Verification, Enabling Fraudulent Quorum and Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships two stub implementations — `validatePerasVote` and `validatePerasCert` — that perform no cryptographic verification whatsoever. An unprivileged peer connected via the ObjectDiffusion mini-protocol can craft `PerasVote` messages that impersonate any pool present in the stake distribution, accumulate enough fake stake to trigger quorum, and cause the receiving node to forge and accept a fraudulent Peras certificate. Because Peras certificates directly inflate chain weight in `WeightedSelectView`, the node may then switch to an adversarially-chosen chain.

---

### Finding Description

**Root cause — `validatePerasVote` stub:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check performed is a `Map.lookup` of `pvVoteVoterId` in `PerasVoteStakeDistr`. No signature is verified, no committee membership is checked, and no VRF proof is validated. Any peer that knows a pool's `KeyHash StakePool` (which is public on-chain data) can craft a `PerasVote` that passes this check and receives the full stake weight of that pool.

**Root cause — `validatePerasCert` stub:** [2](#0-1) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

Every inbound certificate is unconditionally accepted. No aggregate BLS signature, no VRF output, no committee membership is checked.

**Inbound vote path — `processVotes`:** [3](#0-2) 

`processVotes` filters out already-seen vote IDs (deduplication by `(roundNo, voterId)`) and then calls `validateVote` — which is wired to `validatePerasVote mkPerasParams sd vote` — on every new vote. Because the stub always succeeds for any known pool ID, all crafted votes pass and are forwarded to `addVote`. [4](#0-3) 

**Inbound cert path — `processCerts`:** [5](#0-4) 

`processCerts` calls `validatePerasCert mkPerasParams`, which always returns `Right`, so every inbound certificate is accepted and forwarded to `addCert`.

**Vote aggregation — quorum forging:** [6](#0-5) 

`updateTargetVoteTally` deduplicates by `PerasVoteId = (roundNo, voterId)`. An attacker sending one crafted vote per distinct pool ID in the stake distribution can accumulate the full combined stake of all those pools. Once `stakeAboveThreshold` is satisfied, `forgePerasCert` is called and a `ValidatedPerasCert` is produced.

**Chain selection impact:** [7](#0-6) 

`wsvTotalWeight = blockNo + wsvWeightBoost`. A fraudulent certificate adds `perasWeight` to any block the attacker names, potentially making a shorter adversarial fork appear heavier than the honest chain. [8](#0-7) 

`chainSelSync` processes the certificate, adds it to `PerasCertDB`, and calls `chainSelectionForBlock` for the boosted block, potentially switching the node's selection.

---

### Impact Explanation

An unprivileged peer can impersonate any number of pools in the public stake distribution, send crafted `PerasVote` messages for an adversarially-chosen block, trigger quorum, and cause the receiving node to forge a `ValidatedPerasCert` that boosts that block's chain weight. This directly manipulates chain selection: the node may switch to a non-canonical fork that carries the fraudulent boost. This is a **High** chain-selection bug — an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

The attack requires only a network connection to a Peras-enabled node and knowledge of pool key hashes, which are public on-chain data. No stake, no keys, and no privileged access are needed. The attacker must send enough distinct pool-impersonating votes to exceed the quorum threshold, which is bounded by the number of pools in the stake distribution. This is straightforward to automate. Likelihood is **High** once Peras is enabled on a live network.

---

### Recommendation

1. **`validatePerasVote`**: Implement full cryptographic verification — verify the vote signature against the pool's registered VRF/KES key, verify committee membership via the WFALS eligibility proof, and verify the VRF output for non-persistent members. The `CryptoSupportsVotingCommittee` class already provides `verifyVote` for this purpose.

2. **`validatePerasCert`**: Implement full aggregate BLS signature verification and VRF output batch verification using `implVerifyCert` from `Ouroboros.Consensus.Committee.WFALS`, which already performs these checks correctly.

3. **`implAddVote` / `implAddCert`**: The TODO comments at lines 172–173 of `PerasVoteDB/Impl.hs` and 167–168 of `PerasCertDB/Impl.hs` acknowledge this gap; these should be resolved before Peras is enabled on any production network. [9](#0-8) 

---

### Proof of Concept

**Setup**: A private testnet with Peras enabled. Attacker has a network connection to an honest node. The stake distribution contains pools `P1, P2, ..., Pn` with combined stake exceeding the quorum threshold.

**Steps**:

1. Attacker reads the public stake distribution to obtain pool key hashes `{P1, ..., Pn}` and their stakes.

2. Attacker selects an adversarial block `B_adv` on a fork shorter than the honest chain.

3. For each pool `Pi`, attacker crafts:
   ```
   PerasVote { pvVoteRound = R, pvVoteBlock = B_adv, pvVoteVoterId = Pi }
   ```
   No signing key is needed — the vote carries no signature field in the current stub.

4. Attacker sends all crafted votes to the honest node via the ObjectDiffusion mini-protocol.

5. `processVotes` filters out none (all are new IDs), calls `validatePerasVote` on each — all pass because each `Pi` is in the stake distribution.

6. Each vote is added to `PerasVoteDB`. `updateTargetVoteTally` accumulates stake. Once total stake exceeds the quorum threshold, `forgePerasCert` is called and a `ValidatedPerasCert` for `B_adv` is produced.

7. `addPerasVoteWithAsyncCertHandling` triggers `chainSelSync`, which adds the certificate to `PerasCertDB` and calls `chainSelectionForBlock` for `B_adv`.

8. `weightedSelectView` now computes `wsvTotalWeight(B_adv chain) = blockNo + perasWeight`, which may exceed the honest chain's weight, causing the node to switch to the adversarial fork.

**Expected result**: The honest node switches to the adversarial fork `B_adv` despite it being shorter, because the fraudulent Peras boost inflates its chain weight beyond the honest chain's weight.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L108-113)
```haskell
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L430-459)
```haskell
updateTargetVoteTally ::
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteTally blk ->
  PerasTargetVoteTally blk
updateTargetVoteTally
  vote
  ptvt@PerasTargetVoteTally
    { ptvtVotes
    , ptvtTarget
    , ptvtTotalStake
    } =
    assert (getPerasVoteTarget vote == ptvtTarget) $ do
      ptvt
        { ptvtVotes = pvaVotes'
        , ptvtTotalStake = pvaTotalStake'
        }
   where
    swapVote =
      Map.insertLookupWithKey
        (\_k old _new -> old)
        (getPerasVoteId vote)

    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
