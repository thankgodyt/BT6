### Title
Unconditional Peras Certificate Acceptance Allows Any Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, meaning every inbound Peras certificate passes validation regardless of its content. Any unprivileged peer can send crafted certificates via the `PerasCertDiffusion` mini-protocol, causing the receiving node to accept them, store them in the `PerasCertDB`, and trigger chain selection for the boosted block — potentially causing the node to prefer a non-canonical adversarial chain when Peras is enabled.

---

### Finding Description

**Root cause — stub validation always succeeds:**

The degenerate instance in `SupportsPeras.hs` implements `validatePerasCert` as:

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

This is the only instance of `BlockSupportsPeras` in the codebase (marked as a temporary degenerate instance for all `blk`). No cryptographic signature, quorum proof, committee membership, or round-number plausibility check is performed.

**Production inbound path uses this stub:**

`makePerasCertPoolWriterFromChainDB` — the writer used in the live node — passes `validatePerasCert mkPerasParams` as the validation function:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on each certificate and, if all pass (which they always do), calls `addCert` — here `ChainDB.addPerasCertAsync` — for each one. [3](#0-2) 

**This writer is wired into the live node's `PerasCertDiffusion` client handler:**

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [4](#0-3) 

Any peer that connects and speaks the `PerasCertDiffusion` protocol can push certificates through this path.

**Accepted certificates trigger chain selection:**

`chainSelSync` processes `ChainSelAddPerasCert` messages by adding the certificate to the `PerasCertDB` and then calling `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

The CHANGELOG confirms: *"Make the ChainDB aware of the PerasCertDB, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length."* [6](#0-5) 

The default `perasWeight` is `PerasWeight 15`, meaning each injected certificate adds 15 units of weight to the boosted block's chain fragment. [7](#0-6) 

**`addPerasCertAsync` is the ChainDB entry point:** [8](#0-7) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Connect to a victim node via the `PerasCertDiffusion` mini-protocol.
2. Send a crafted `PerasCert` with `pcCertRound` set to any round not yet in the DB, and `pcCertBoostedBlock` pointing to an adversarial block the attacker has already served via ChainSync/BlockFetch.
3. `validatePerasCert` unconditionally returns `Right`, so `processCerts` calls `ChainDB.addPerasCertAsync` with the fake certificate.
4. `chainSelSync` adds the certificate to the `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block, giving it a weight advantage of 15 over the honest chain.
5. If the adversarial chain is within the rollback window and the weight boost tips the comparison, the node switches to the adversarial chain.

This is a **chain selection manipulation** bug: an unprivileged peer can cause an honest node to prefer a non-canonical chain by injecting fake Peras certificates that bypass all cryptographic and structural validation. This violates the core Peras security invariant that only legitimately quorum-certified blocks should receive a weight boost.

**Scope note:** The CHANGELOG states Peras is disabled by default. The attack is effective only on nodes with Peras enabled. However, the diffusion protocol is fully wired up in production code, the stub validation is the only implementation, and the feature is intended for production activation.

---

### Likelihood Explanation

- **Reachability:** Any peer that can establish a node-to-node connection can speak the `PerasCertDiffusion` protocol. No special privileges are required.
- **Precondition:** Peras must be enabled via the feature flag. This is not the current mainnet default, but is the intended production state and may be enabled on testnets or by operators experimenting with Peras.
- **Ease of exploit:** Trivial. The attacker only needs to send a well-formed `PerasCert` CBOR message with an arbitrary round number and a target block hash. No cryptographic material is needed because `validatePerasCert` performs no checks.
- **One-cert-per-round limit:** The DB deduplicates by round number, so only one certificate per round is accepted. An attacker can still inject one fake certificate per Peras round (every 90 slots by default), which is sufficient to persistently boost an adversarial block.

---

### Recommendation

1. **Do not wire the `PerasCertDiffusion` inbound handler to a stub validator.** Until real certificate validation (BLS aggregate signature verification, committee membership proof, quorum threshold check) is implemented, the inbound handler should reject all certificates or be fully disabled at the protocol negotiation level.
2. **Replace the degenerate `validatePerasCert` stub** with a function that returns `Left PerasValidationErr` (reject all) until the real implementation is ready, rather than `Right` (accept all).
3. **Gate the `PerasCertDiffusion` protocol** behind the same feature flag that gates Peras chain selection, so that the inbound path is unreachable when Peras is disabled.

---

### Proof of Concept

**Setup:** A private testnet with Peras enabled. Attacker controls one peer connected to the victim node.

**Steps:**

1. Attacker serves an adversarial block `B_adv` to the victim via ChainSync/BlockFetch (block is in the victim's VolatileDB but not selected).
2. Attacker opens the `PerasCertDiffusion` mini-protocol channel to the victim.
3. Attacker sends a `PerasCert` with:
   - `pcCertRound = <any round not yet in victim's PerasCertDB>`
   - `pcCertBoostedBlock = headerPoint B_adv`
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally. [9](#0-8) 
5. `ChainDB.addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message.
6. `chainSelSync` adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for `B_adv`, giving its chain fragment a weight of `length + 15`. [10](#0-9) 
7. If `B_adv`'s chain (with the injected boost) is now heavier than the current selection, the victim switches to the adversarial chain.

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

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
