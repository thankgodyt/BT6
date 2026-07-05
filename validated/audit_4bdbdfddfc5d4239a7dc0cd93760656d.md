### Title
Unconditional Peras Certificate Acceptance Enables Arbitrary Chain Weight Inflation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally accepts every inbound certificate without performing any cryptographic or eligibility check. An unprivileged peer can craft certificates boosting arbitrary blocks on a minority fork, causing the victim node to inflate the Peras weight of that fork and switch away from the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must authenticate a Peras certificate before it influences chain selection. The sole production instance — a universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as a stub that always returns `Right`:

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

No signature is verified, no committee membership is checked, no round validity is enforced, and no boosted-block eligibility is confirmed. The same instance is the only one in the codebase — there is no more-specific Cardano block instance that overrides it. [2](#0-1) 

The inbound certificate processing path in `processCerts` (called by `makePerasCertPoolWriterFromChainDB`) passes this stub as the `validateCert` argument:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` filters out certs whose round number is already stored, then calls `validateCert` on the remainder. Because `validatePerasCert` always returns `Right`, every novel-round certificate from any peer is accepted: [4](#0-3) 

Once accepted, the certificate is stored in `PerasCertDB` and `implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certs via `mkPerasWeightSnapshot`. `addToPerasWeightSnapshot` uses `Map.insertWith (<>)`, so each accepted cert additively contributes `perasWeight params` to the boosted block's weight: [5](#0-4) 

Chain selection then uses `weightedSelectView` / `wsvTotalWeight` to compare fragments, preferring the heavier one: [6](#0-5) 

An attacker who sends one crafted certificate per round (each boosting a block on their fork) can accumulate enough `PerasWeight` to make their fork appear heavier than the honest chain, causing `chainSelSync` to switch the victim node to the attacker's fork: [7](#0-6) 

The same stub problem exists for `validatePerasVote` — it only checks that the voter ID appears in the stake distribution but verifies no cryptographic signature — allowing forged votes to reach quorum and generate fraudulent certificates internally: [8](#0-7) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can inject one crafted `PerasCert` per round (each naming any block on a minority fork as the boosted block). Each accepted certificate adds `perasWeight params` to that fork's `PerasWeightSnapshot`. After enough rounds the attacker's fork accumulates a `wsvTotalWeight` exceeding the honest chain's, causing the victim node to irreversibly switch to the attacker-controlled fork. This is a **critical chain-selection safety failure**: an honest node accepts an invalid ledger state driven entirely by unauthenticated network input, with no stake majority or key compromise required.

---

### Likelihood Explanation

Peras is currently behind a feature flag (`rnFeatureFlags` in `RunNodeArgs`) and disabled by default. However, the stub is the only production instance and is wired directly into the live diffusion path (`makePerasCertPoolWriterFromChainDB`). Any node operator who enables Peras is immediately exposed. The attack requires only a TCP connection to the node's peer port and knowledge of any block hash on the target chain — both trivially available to any network participant.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` before enabling Peras in production. At minimum, verify the certificate's aggregate signature against the committee's public keys and confirm the boosted block was eligible for that round.
2. **Implement real cryptographic validation** in `validatePerasVote` — verify the VRF proof and vote signature, not just stake-distribution membership.
3. **Gate the feature flag** so that the Peras diffusion miniprotocol handlers are unreachable unless a fully validated `BlockSupportsPeras` instance is in scope, preventing the stub from being used in any live network context.
4. Track the referenced issues (`tweag/cardano-peras#73` and `#120`) as security-blocking before any Peras mainnet activation.

---

### Proof of Concept

A node with Peras enabled, connected to a malicious peer, can be driven to switch chains as follows:

1. Attacker connects to the victim node via the Peras certificate miniprotocol.
2. For rounds `r = 0, 1, 2, …, N`, attacker sends `PerasCert { pcCertRound = r, pcCertBoostedBlock = attackerBlockPoint }` where `attackerBlockPoint` is the tip of the attacker's fork.
3. `processCerts` calls `validatePerasCert mkPerasParams` on each cert; all return `Right` unconditionally. [9](#0-8) 
4. Each cert is stored in `PerasCertDB`; `implGetWeightSnapshot` accumulates `N × perasWeight params` onto `attackerBlockPoint`. [10](#0-9) 
5. `chainSelSync` is triggered for the boosted block; `weightedSelectView` computes `wsvTotalWeight` for the attacker's fragment as `blockNo + N × perasWeight`, which exceeds the honest chain's `blockNo + 0`. [11](#0-10) 
6. The victim node switches to the attacker's fork, accepting an invalid ledger state.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L163-173)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```
