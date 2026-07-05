### Title
Unconditional `validatePerasCert` Acceptance Bypasses Peras Certificate Quorum Verification, Enabling Unauthorized Chain Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every inbound certificate, regardless of quorum stake, aggregate signature validity, or committee membership. Any unprivileged peer can send a crafted `PerasCert` that is accepted without verification, injected into the `PerasCertDB`, and used to boost an arbitrary block's chain-selection weight, potentially causing the honest node to switch to an adversary-controlled fork.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the `BlockSupportsPeras` instance for all `blk` implements `validatePerasCert` as an unconditional success:

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
``` [1](#0-0) 

This is the function wired into the **production network-facing certificate ingestion path** in `makePerasCertPoolWriterFromChainDB`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` partitions results into errors and successes; since `validatePerasCert` never returns `Left`, every certificate from every peer is treated as valid and forwarded to `addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block: [4](#0-3) 

The accepted certificate contributes a boost of `perasWeight params` (default `15`) to the targeted block's chain-selection weight via `getWeightSnapshot`: [5](#0-4) 

The correct validation path — checking aggregate BLS signatures, committee membership, and quorum stake — exists in `implVerifyCert` for the `WFALS` and `EveryoneVotes` committee schemes, but is never invoked on the inbound certificate path. [6](#0-5) 

The analog to the external report is exact: just as `getGuardedValue` returns a seemingly valid `(0, 0)` when the guardian threshold is not met, `validatePerasCert` returns a seemingly valid `Right ValidatedPerasCert` when no quorum threshold has been verified at all.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the adversary's fork. The honest node will:

1. Accept the certificate unconditionally (no signature or quorum check).
2. Store it in the `PerasCertDB` with a boost weight of 15.
3. Trigger chain selection for the boosted block.
4. Potentially switch to the adversary's fork if the boosted fork's total weight exceeds the current chain.

This is a **bypass of Peras certificate verification** enabling unauthorized chain boost and potential chain-selection manipulation — an honest node can be made to prefer a non-canonical chain beyond the intended security assumptions of the Peras protocol.

**Impact: High** — chain-selection bug triggered by an unprivileged peer via a crafted protocol message.

---

### Likelihood Explanation

The entry point is the Peras certificate miniprotocol, reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` with a chosen `pcCertRound` and `pcCertBoostedBlock`. The `TODO` comment and linked issue confirm this is a known incomplete stub, not a deliberate design choice, making it a real production gap rather than a theoretical one.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that:

1. Verifies the aggregate BLS signature against the declared voter set (as done in `implVerifyCert` for `WFALS`/`EveryoneVotes`).
2. Checks that the declared voters constitute a quorum (total stake ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`) using `stakeAboveThreshold`.
3. Verifies each voter's committee membership and VRF eligibility proof.
4. Returns `Left` with a descriptive `PerasValidationErr` on any failure, causing `processCerts` to throw `PerasCertValidationError` and disconnect the offending peer. [7](#0-6) 

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node running the Peras-enabled consensus stack.
2. Connect as a peer via the Peras certificate object-diffusion miniprotocol.
3. Send a CBOR-encoded `PerasCert` with:
   - `pcCertRound = <any round number>`
   - `pcCertBoostedBlock = <hash of a block on an adversary fork>`
4. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{..., vpcCertBoost = 15}`.
5. The certificate is forwarded to `addPerasCertAsync chainDB`, enqueued in `cdbChainSelQueue`, and processed by `chainSelSync`.
6. `chainSelectionForBlock` is triggered for the adversary's boosted block.
7. If the adversary's fork length + boost weight exceeds the honest chain's weight, the node switches forks.

The root cause is confirmed at: [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-494)
```haskell
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
```
