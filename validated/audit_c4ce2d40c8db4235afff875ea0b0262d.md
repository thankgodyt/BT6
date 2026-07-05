Looking at the original vulnerability class — an external "oracle" (price feed) used to determine a value (exchange rate) that drives a critical decision (swap), where the oracle input is not properly validated — I need to find an analog in Ouroboros Consensus where an external peer-supplied "view" drives chain selection without proper validation.

Let me examine the Peras certificate validation and chain selection path.

### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Unauthenticated Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the default `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every certificate received from a peer, performing zero cryptographic or committee-membership checks. When Peras is enabled, any unprivileged peer can inject a crafted certificate targeting a block on an adversarial fork. The certificate is stored in `PerasCertDB`, its weight boost is applied to that block via `PerasWeightSnapshot`, and chain selection (`WeightedSelectView.preferCandidate`) may then switch the honest node to the attacker's chain.

---

### Finding Description

**Root cause — stub validator always succeeds:** [1](#0-0) 

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

Every certificate from every peer is accepted. The `vpcCert = cert` field carries the attacker-chosen `pcCertBoostedBlock` (the target block point), and `vpcCertBoost = perasWeight params` applies the configured weight boost to that block.

**Entry path — network-facing `processCerts` calls the stub:** [2](#0-1) 

`opwAddObjects` calls `processCerts` with `(validatePerasCert mkPerasParams)` as the validator. Any peer connected via the object-diffusion mini-protocol can submit certificates here. Because the validator never rejects, every submitted certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`.

**Chain selection uses the injected weight:** [3](#0-2) 

`WeightedSelectView.preferCandidate` compares `wsvTotalWeight` (block number + `wsvWeightBoost`). The weight boost is read from `PerasWeightSnapshot`, which is populated directly from the `PerasCertDB` contents: [4](#0-3) 

**ChainSel is triggered for the boosted block:** [5](#0-4) 

When a certificate is added, `chainSelSync` looks up the boosted block in `VolatileDB` and calls `chainSelectionForBlock`, which re-runs chain selection with the new weight snapshot. If the attacker's fork now has higher total weight, the node switches to it.

**The analog to the original oracle vulnerability:**

| Original (rsETH) | Ouroboros Consensus analog |
|---|---|
| Price oracle provides exchange rate | Peras certificate provides weight boost |
| Oracle input not verified against true market state | Certificate not verified against committee/crypto |
| MANAGER calls `swapAssetWithinDepositPool` with oracle rate | Peer submits certificate via object-diffusion protocol |
| Node accepts swap at wrong price | Node applies weight boost to attacker's block |
| Profitable arbitrage / fund drain | Chain selection switches to adversarial fork |

---

### Impact Explanation

**High — chain selection bug.** An unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended Ouroboros security assumptions. By injecting a fake certificate for a block on an adversarial fork, the attacker inflates that fork's `wsvTotalWeight` by `perasWeight params` (a non-zero configured value). If the adversarial fork's boosted weight exceeds the honest chain's weight, `preferCandidate` returns `ShouldSwitch` and the node rolls back to the attacker's chain. This can enable double-spend or permanent divergence from the honest chain.

---

### Likelihood Explanation

Peras is gated behind a feature flag (`rnFeatureFlags`) and is disabled by default. However, the code is present in the production codebase, the object-diffusion protocol handler is wired up, and the stub is the only `validatePerasCert` implementation for all block types (including `HardForkBlock`/Cardano blocks). Any operator enabling Peras exposes this path to every connected peer with no additional privilege required. The attack requires only the ability to send a well-formed `PerasCert` message over the network.

---

### Recommendation

1. **Do not enable Peras in production until `validatePerasCert` performs real cryptographic validation** — verifying committee membership via VRF sortition, the aggregate signature over the certificate body, and that the quorum threshold is met.
2. Track the implementation in the referenced issue (`cardano-peras/issues/120`) and gate the object-diffusion handler on both the feature flag *and* a non-stub validator being in place.
3. Consider the same pattern used for `validatePerasVote`: at minimum, reject certificates whose signer is not in the current committee stake distribution before storing them.

---

### Proof of Concept

1. Start a node with Peras enabled (`rnFeatureFlags` set).
2. Connect as a peer via the object-diffusion mini-protocol.
3. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on an adversarial fork (any block hash in the node's `VolatileDB`).
4. Submit the certificate. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
5. `ChainDB.addPerasCertAsync` stores the certificate; `implGetWeightSnapshot` now includes the boost for the adversarial block.
6. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block. `constructPreferableCandidates` computes `WeightedSelectView` with the inflated `wsvWeightBoost`.
7. If `wsvTotalWeight(adversarial) > wsvTotalWeight(honest)`, `preferCandidate` returns `ShouldSwitch` and the node rolls back to the adversarial chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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
