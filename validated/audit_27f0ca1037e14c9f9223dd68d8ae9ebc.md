### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain-Selection Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Any unprivileged peer can send a crafted `PerasCert` over the live `PerasCertDiffusion` mini-protocol, have it accepted as "validated," and cause the receiving node to apply a weight boost of 15 blocks to an arbitrary chain fragment during chain selection. This is a direct bypass of Peras certificate verification that enables unauthorized chain-selection manipulation.

---

### Finding Description

**Root cause — stub validator always succeeds:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the `BlockSupportsPeras` instance for all `StandardHash blk` blocks implements `validatePerasCert` as an unconditional stub:

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

No signature is checked, no quorum is verified, no committee membership is validated, and no round/slot bounds are enforced. Every certificate, regardless of content, is wrapped in `ValidatedPerasCert` and returned as valid.

**Attacker-controlled entry path — live mini-protocol:**

The `hPerasCertDiffusionClient` handler in `mkHandlers` wires this stub directly into the production node-to-node diffusion layer:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` passes every cert that is not already in the DB through `validateCert`, and since the stub always returns `Right`, every new cert is immediately forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain-selection consequence:**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it by adding the cert to `PerasCertDB` and then calling `chainSelectionForBlock` for the cert's `pcCertBoostedBlock`: [5](#0-4) 

Chain selection uses `WeightedSelectView`, which adds `wsvWeightBoost` (sourced from the cert's `vpcCertBoost = perasWeight params = PerasWeight 15`) to the total weight of the boosted fragment: [6](#0-5) 

A fragment boosted by a crafted cert appears 15 blocks heavier than it actually is, which is sufficient to cause the node to switch to a fork it would otherwise reject.

---

### Impact Explanation

**Impact: High — Chain selection bug enabling non-canonical chain preference.**

An unprivileged peer can craft a `PerasCert` pointing to any block hash in the VolatileDB and send it over the `PerasCertDiffusion` mini-protocol. The receiving node will:

1. Accept the cert unconditionally (no validation).
2. Apply a `PerasWeight 15` boost to the boosted block's chain fragment.
3. Re-run chain selection, potentially switching to a fork that is up to 15 blocks shorter than the current selection.

This violates the chain-selection security assumption: an honest node should only prefer a candidate chain if it is genuinely heavier under the Peras protocol rules. A single malicious peer with no stake or keys can force a chain switch to a weaker fork, breaking the safety guarantee that the selected chain is the canonical one.

---

### Likelihood Explanation

**Likelihood: 2 (Low-to-Medium for private testnet / Peras-enabled deployments).**

The `PerasCertDiffusion` mini-protocol is wired into the production handler set. The vulnerability is fully reachable on any node where Peras is enabled (e.g., a private testnet running with Peras feature flags). The exploit requires only a network connection to the target node — no keys, no stake, no privileged access. The CHANGELOG confirms Peras is "disabled by default" on mainnet today, which limits current exposure, but the code is production-grade and the attack path is complete.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's cryptographic signature(s) against the committee's keys.
2. That the signers constitute a valid quorum (total stake ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. That the boosted block's slot falls within the valid range for the certificate's round number.
4. That the certificate round is not older than `perasCertMaxRounds` from the current round.

Until real validation is implemented, the `PerasCertDiffusion` inbound handler should be disabled or should reject all inbound certificates rather than accepting them unconditionally.

---

### Proof of Concept

**Attacker steps (private testnet with Peras enabled):**

1. Connect to the target node as a normal peer (no special privileges).
2. Negotiate the `PerasCertDiffusion` mini-protocol.
3. Send a `PerasCert` message with:
   - `pcCertRound` = any round number not yet in the target's `PerasCertDB`.
   - `pcCertBoostedBlock` = the `Point` of a block on a shorter competing fork that is present in the target's VolatileDB.
4. The target node calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}` unconditionally.
5. `addPerasCertAsync` queues the cert; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
6. `weightedSelectView` computes the boosted fragment's total weight as `blockNo + 15`; if this exceeds the current selection's weight, the node switches to the attacker-chosen fork.

**Relevant code path summary:**

```
peer sends PerasCert
  → objectDiffusionInbound (NodeToNode.hs:375)
  → processCerts (PerasCert.hs:164)
  → validatePerasCert mkPerasParams cert  ← always Right (SupportsPeras.hs:353)
  → ChainDB.addPerasCertAsync (PerasCert.hs:132)
  → chainSelSync / ChainSelAddPerasCert (ChainSel.hs:483)
  → chainSelectionForBlock with PerasWeight 15 boost (SelectView.hs:57)
  → node switches to attacker-chosen fork
```

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
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
