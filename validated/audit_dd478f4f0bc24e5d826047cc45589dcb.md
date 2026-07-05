### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Fake Chain-Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` degenerate instance implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or structural checks on inbound Peras certificates. Because this stub is wired directly into the production `ObjectPoolWriter` path used by `makePerasCertPoolWriterFromChainDB`, any unprivileged peer can send a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` that will be accepted, stored in the `PerasCertDB`, and used to artificially inflate the Peras weight of any block during chain selection. This allows a peer to make an honest node prefer a non-canonical chain.

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The `instance StandardHash blk => BlockSupportsPeras blk` in `SupportsPeras.hs` is explicitly labelled a "degenerate instance … to get things to compile" and its `validatePerasCert` implementation returns `Right` for every input without inspecting the certificate at all:

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

No quorum check, no aggregate-signature verification, no round-number plausibility check, and no boosted-block existence check is performed.

**Production wiring — `makePerasCertPoolWriterFromChainDB`:**

The production `ObjectPoolWriter` for inbound Peras certificates passes this stub directly as the `validateCert` argument:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions results into errors and successes; because `validatePerasCert` never produces an error, every inbound certificate is unconditionally added to the `PerasCertDB`. [3](#0-2) 

**Chain-selection impact — `chainSelSync` and `preferAnchoredCandidate`:**

Once a certificate is stored, `chainSelSync` is triggered. It reads the boosted block from the `VolatileDB` and calls `chainSelectionForBlock`, which uses `preferAnchoredCandidate`. That function, when the `PerasWeightSnapshot` is non-empty, computes `weightedSelectView` over the suffix of each candidate fragment and compares total weights (block number + Peras boost):

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      Just (_,_,oursSuffix,candSuffix) ->
        case preferCandidate cfg
               (weightedSelectView cfg weights oursSuffix)
               (weightedSelectView cfg weights candSuffix) of
          ShouldSwitch r -> ShouldSwitch (Left r)
          ...
``` [4](#0-3) 

A fake certificate that boosts a block on an adversary's fork by `perasWeight` units can make that fork's total weight exceed the honest chain's, causing the node to switch. [5](#0-4) 

### Impact Explanation

When Peras is enabled via the experimental feature-flag mechanism, an unprivileged peer can inject an arbitrary number of fake `PerasCert` objects, each boosting any block by `perasWeight` units. Because the boost accumulates additively (`wsvTotalWeight = BlockNo + ΣPerasWeight`), a peer can make a short adversarial fork appear heavier than the honest chain, causing the victim node to perform a chain switch to a non-canonical chain. This is a **High** chain-selection integrity failure: an honest node is made to prefer a less-secure chain solely through crafted network messages, with no stake majority or key compromise required. [6](#0-5) 

### Likelihood Explanation

Peras is currently disabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference`), so the attack surface is not exposed on mainnet today. However, the production code path is fully wired and the feature can be enabled via `rnFeatureFlags`. Any operator enabling Peras on a private testnet or future mainnet deployment immediately exposes this path to every connected peer. No privileged access, key material, or stake is required — only the ability to send a well-formed `PerasCert` CBOR message over the object-diffusion mini-protocol. [7](#0-6) 

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate vote signature over `(electionId, candidate)` using the committee's aggregate verification key.
2. Confirms that the set of voters in the certificate holds sufficient stake to meet the quorum threshold (`stakeAboveThreshold`).
3. Checks that `pcCertRound` and `pcCertBoostedBlock` are consistent with the current ledger state (round is not in the future, boosted block exists and is within the valid window).

Until the real implementation is ready, the stub should be replaced with `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that enabling the feature flag does not silently open the attack surface. [8](#0-7) 

### Proof of Concept

1. Enable Peras via `rnFeatureFlags` on a private testnet node.
2. Connect a malicious peer that speaks the object-diffusion mini-protocol for Peras certificates.
3. The peer sends a batch containing a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = <hash of a block on the adversary's fork> }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })`.
5. The cert is stored in `PerasCertDB`; `chainSelSync` fires and calls `chainSelectionForBlock` for the boosted block.
6. `preferAnchoredCandidate` computes `wsvTotalWeight` for the adversary's suffix as `BlockNo(fork_tip) + perasWeight`, which exceeds the honest chain's `BlockNo(honest_tip) + 0`.
7. The node switches to the adversary's fork.

Repeating step 3 with additional fake certificates for the same or different blocks multiplies the injected weight without limit, since each unique `pcCertRound` is treated as a distinct certificate. [3](#0-2)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
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
