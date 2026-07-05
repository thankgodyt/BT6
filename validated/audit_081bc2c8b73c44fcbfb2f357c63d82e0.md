### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. An unprivileged peer can submit a crafted `PerasCert` over the network that passes this non-existent validation gate, gets stored in the `PerasCertDB`, and triggers chain selection for the boosted block — potentially causing an honest node to switch to a fork it would not otherwise prefer.

---

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` provides a degenerate implementation of `validatePerasCert` that is explicitly marked as a TODO stub:

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

This stub is wired directly into the network-facing certificate ingestion path. In `makePerasCertPoolWriterFromChainDB`, inbound certificates from peers are processed via `processCerts`, which calls `validatePerasCert mkPerasParams` as its validation gate:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [2](#0-1) 

Because `validatePerasCert` always returns `Right`, `processCerts` classifies every inbound certificate as valid and forwards it to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for the background chain-selection thread: [4](#0-3) 

The background thread processes it in `chainSelSync` (`ChainSelAddPerasCert` branch), stores it in the `PerasCertDB`, and calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

Chain selection uses the `PerasWeightSnapshot` to compare candidate fragments. A certificate adds `vpcCertBoost` (set to `perasWeight params` by the stub) to the total weight of the boosted block's chain: [6](#0-5) 

The same stub problem exists for `validatePerasVote`, though the vote path requires accumulating enough stake to reach quorum before a certificate is forged: [7](#0-6) 

---

### Impact Explanation

**Impact: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

An attacker who is a connected peer can craft a `PerasCert` naming any block hash present in the node's `VolatileDB` as the boosted block. Because `validatePerasCert` performs no signature, committee-membership, round-number, or quorum verification, the certificate is accepted unconditionally. The injected boost (`perasWeight params`) is added to the candidate chain's total weight. If a competing fork exists in the `VolatileDB`, the attacker can make it heavier than the current selection, causing the node to roll back and switch to that fork. This directly violates the chain-selection invariant that weight boosts are only granted to blocks certified by a legitimate quorum of stake-weighted committee members.

---

### Likelihood Explanation

**Likelihood: High** — The entry path is the standard object-diffusion mini-protocol for Peras certificates, reachable by any connected peer without any credentials. No stake, no keys, and no prior knowledge beyond a valid block hash in the target node's `VolatileDB` are required. The stub is in the default `BlockSupportsPeras` instance used for all block types, and the TODO comment confirms it is intentionally incomplete production code, not a test-only path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that checks:
1. The certificate's cryptographic signature (aggregate BLS or equivalent) against the claimed committee members.
2. That the signers are eligible committee members for the stated round (VRF-based committee selection).
3. That the aggregate stake of the signers meets the quorum threshold.
4. That the round number is within the valid window relative to the current chain tip.

Until real validation is in place, the `addPerasCertAsync` path should reject all externally supplied certificates, or the object-diffusion server for Peras certificates should not be activated in production builds.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node with a two-block VolatileDB: block A (current tip, chain length 5) and block B (fork tip, chain length 4, one block shorter than A's chain).
2. From a connected peer, send a `PerasCert` with `pcCertBoostedBlock = blockPoint B` and any `pcCertRound`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is forwarded to `ChainDB.addPerasCertAsync`.
5. `chainSelSync` stores the cert and calls `chainSelectionForBlock` for block B.
6. `constructPreferableCandidates` computes the `WeightedSelectView` for the fork containing B; the injected boost raises its `wsvTotalWeight` above the current chain's weight.
7. `switchTo` commits the fork as the new selection — the node has rolled back to block B's fork despite it being shorter. [8](#0-7) [1](#0-0) [9](#0-8) [3](#0-2) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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
