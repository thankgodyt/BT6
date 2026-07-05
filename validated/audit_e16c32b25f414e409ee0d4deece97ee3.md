### Title
Unconditional Peras Certificate Acceptance Enables Unauthorized Chain-Selection Boost by Unprivileged Peer — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate inbound path accepts any certificate from any peer without performing cryptographic validation. The sole `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right`, meaning a crafted certificate for an arbitrary block passes "validation" and is forwarded into chain selection, where it grants that block a configurable weight boost (`PerasWeight 15` by default). An unprivileged peer can therefore force an honest node to prefer a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve an inbound Peras certificate before it is stored and acted upon. The only instance in the codebase is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` that explicitly skips all validation:

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

No committee membership check, no BLS aggregate signature verification, no VRF eligibility proof, and no round-number plausibility check are performed. Every certificate is stamped `ValidatedPerasCert` with the full `perasWeight params` boost.

This stub is wired directly into the production node-to-node certificate diffusion handler:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

Inside `makePerasCertPoolWriterFromChainDB`, the writer calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function and then forwards accepted certificates to `ChainDB.addPerasCertAsync`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

Once a certificate reaches the ChainDB, `chainSelSync` triggers a full chain-selection pass for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The default `mkPerasParams` sets `perasWeight = PerasWeight 15`, meaning a boosted block's chain is treated as 15 blocks heavier than it actually is: [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` naming any block hash present in the target node's VolatileDB. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored in the `PerasCertDB`, and immediately used to re-run chain selection for the named block. The named block's chain gains a `PerasWeight 15` advantage, which can cause the node to switch away from the canonical chain to a shorter fork — a chain-selection safety failure. Because one certificate is accepted per round (the `PerasCertDB` deduplicates by `PerasRoundNo`), an attacker can issue one forged certificate per Peras round (every 90 slots by default), continuously steering the victim node toward attacker-chosen forks.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol (`hPerasCertDiffusionClient`) is active in the production node-to-node handler for any peer that negotiates a compatible `NodeToNodeVersion`. No stake, key material, or privileged access is required. The attacker only needs to know a valid block hash in the target's VolatileDB (trivially obtained via the ChainSync protocol) and to be connected as a normal peer.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregated public keys of the claimed voters.
2. That each claimed voter was a member of the elected committee for that round (VRF eligibility proof for non-persistent voters).
3. That the total stake of the voters meets the quorum threshold (`perasQuorumStakeThreshold`).

Until the real implementation is ready, the inbound certificate diffusion handler should be disabled or should reject all certificates, analogous to how the vote handler already neutralises all votes by passing an empty stake distribution (`pure (PerasVoteStakeDistr mempty)`). [6](#0-5) 

---

### Proof of Concept

**Private-testnet reproduction sequence:**

1. Start a node with the Peras certificate diffusion mini-protocol enabled (default production configuration).
2. Connect a malicious peer that speaks the `ObjectDiffusion` protocol for Peras certificates.
3. The malicious peer queries the honest node's current chain via ChainSync to learn a block hash `H` on a short fork that is currently losing chain selection.
4. The malicious peer sends a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint s H }` over the certificate diffusion channel.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` unconditionally. [7](#0-6) 

6. The certificate is forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message.
7. `chainSelSync` runs `chainSelectionForBlock` for block `H`. The fork containing `H` now has `totalWeight = blockNo(H) + 15`, which may exceed the canonical chain's `blockNo(tip)`, causing the node to switch to the attacker-chosen fork. [8](#0-7)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L487-532)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
