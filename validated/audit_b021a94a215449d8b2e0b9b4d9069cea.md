### Title
Peras Certificate Validation Bypass via No-Op `validatePerasCert` Enables Arbitrary Chain-Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — no cryptographic signature, no committee-membership check, no quorum check. This instance is wired directly into the production certificate-ingest path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore send a crafted `PerasCert` naming an arbitrary block, have it accepted as "validated", stored in the `PerasCertDB`, and used to boost that block's weight during chain selection, potentially causing an honest node to switch to a non-canonical fork.

---

### Finding Description

**Root cause — no-op validation**

The `BlockSupportsPeras` instance that covers every block type contains:

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

This is the **only** `BlockSupportsPeras` instance in the codebase; it is a catch-all (`instance StandardHash blk => BlockSupportsPeras blk`) explicitly labelled a "degenerate instance for all blks to get things to compile". [2](#0-1) 

**Production ingest path**

`makePerasCertPoolWriterFromChainDB` — the production writer used when certificates arrive from peers — calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [3](#0-2) 

`processCerts` calls `validateCert` on every inbound certificate; if all pass (they always do), each is timestamped and forwarded to `addPerasCertAsync`: [4](#0-3) 

**Chain-selection consequence**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: the certificate's boosted block is looked up in the `VolatileDB`, and `chainSelectionForBlock` is triggered, which reads the `PerasWeightSnapshot` and calls `preferAnchoredCandidate` / `compareAnchoredFragments` using the injected weight: [5](#0-4) 

`weightedSelectView` adds `wsvWeightBoost` (derived from the attacker-supplied certificate) to `wsvBlockNo` to form `wsvTotalWeight`, which drives the `preferCandidate` comparison: [6](#0-5) 

**Analog to the external report**

| External report | Ouroboros analog |
|---|---|
| Attacker pays fees in a "poisonous" worthless token they created | Attacker sends a crafted `PerasCert` naming any block; `validatePerasCert` always returns `Right` regardless of content |
| SwapFacade accepts the custom token without verifying its value | `processCerts` accepts the certificate without any cryptographic check |
| Result: fee bypass | Result: arbitrary weight boost injected into chain selection |

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to the tip of an adversarial fork.
2. Transmit it via the Peras certificate diffusion mini-protocol.
3. The receiving node's `validatePerasCert` returns `Right` unconditionally.
4. The certificate is stored and its `vpcCertBoost = perasWeight params` is added to the `PerasWeightSnapshot`.
5. Chain selection now sees the adversarial fork as heavier than the honest chain and switches to it.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, potentially adversary-controlled chain, violating the Peras weight-based chain-selection invariant and the honest-chain preference guarantee.

---

### Likelihood Explanation

**Medium.** The Peras certificate diffusion mini-protocol is fully wired into the production `NodeKernel` path. The no-op validation is not gated behind a feature flag at the validation layer — only the weight applied to chain selection is zero when Peras is "disabled" at the parameter level. Once Peras is activated with a non-zero `perasWeight`, the attack is immediately exploitable by any connected peer with no special privileges. The TODO comments and linked issue (`cardano-peras#120`) confirm the gap is known but unresolved.

---

### Recommendation

Replace the no-op `validatePerasCert` with a real implementation that verifies:
- The certificate carries a valid aggregate BLS signature from a quorum of eligible committee members (using `CryptoSupportsAggregateVoteSigning`).
- Each voter's VRF eligibility proof is valid (using `CryptoSupportsBatchVRFVerification` / `linearizeAndVerifyVRFs`).
- The boosted block's slot falls within the valid range for the claimed round.
- The certificate's round number is not in a cooldown period.

Until the real implementation is ready, the certificate ingest path should reject all inbound certificates (return `Left PerasValidationErr`) rather than accept them unconditionally, so that the placeholder cannot be exploited when Peras weight becomes non-zero.

---

### Proof of Concept

1. Connect to a target node running with Peras enabled (non-zero `perasWeight`).
2. Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <tip of adversarial fork>`.
3. Send it via the Peras certificate diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight params}`.
5. `addPerasCertAsync` enqueues the cert; `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `weightedSelectView` computes `wsvTotalWeight = blockNo + perasWeight`, making the adversarial fork heavier.
7. `preferAnchoredCandidate` returns `ShouldSwitch`; the node switches to the adversarial fork. [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
