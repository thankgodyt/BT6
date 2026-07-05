### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Allows Unprivileged Peer to Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production Peras certificate inbound miniprotocol handler calls `validatePerasCert` to authenticate certificates received from peers before adding them to the ChainDB. The only deployed instance of `validatePerasCert` is a stub that unconditionally returns `Right` — it performs no cryptographic, quorum, or committee-membership checks whatsoever. Any unprivileged peer can therefore inject an arbitrary `PerasCert` (pointing to any block, for any round) through the live `hPerasCertDiffusionClient` miniprotocol, causing the receiving node to add the certificate to its `PerasCertDB` and trigger chain selection with a fabricated weight boost, potentially making the node prefer a non-canonical fork.

### Finding Description

**Root cause — stub `validatePerasCert` always returns `Right`**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate a certificate before it is stored. The only concrete instance in the codebase is the catch-all degenerate instance:

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

No BLS signature, no quorum proof, no committee-membership check, no round-number sanity check — every certificate is accepted unconditionally.

**Attacker-controlled entry path**

The production node-to-node protocol wires this directly into the live `hPerasCertDiffusionClient` handler:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validation function to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on each inbound certificate; if all pass (they always do), it calls `addCert . WithArrivalTime now` for each one: [4](#0-3) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

**End-to-end exploit flow**

1. Attacker connects to a victim node as a normal peer (no privileged access required).
2. Attacker sends a crafted `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlock }` via the Peras certificate diffusion miniprotocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
4. The certificate is added to the `PerasCertDB` and `addPerasCertAsync` is called.
5. `chainSelSync` triggers `chainSelectionForBlock` for `adversarialBlock`, giving it a weight boost of 15.
6. If the adversarial fork's boosted weight now exceeds the honest chain's weight, the node switches to the adversarial fork.

The only existing guard is a staleness check (the boosted block must be newer than the immutable tip), which still leaves the entire volatile window (up to *k* = 2160 blocks) as a valid target. [6](#0-5) 

### Impact Explanation

An unprivileged peer can inject one fabricated `PerasCert` per Peras round (deduplication is by round number only). Each injected certificate grants an arbitrary block a `PerasWeight 15` boost in chain selection. By targeting a block on an adversarial fork, the attacker can make the victim node's chain selection prefer that fork over the honest chain, constituting a **chain selection safety failure**: the node accepts and extends a non-canonical chain without any legitimate quorum of stake having voted for it. This directly violates the Peras security guarantee that only blocks backed by a genuine quorum certificate receive a boost.

**Severity: High** — matches "Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

### Likelihood Explanation

- **Attacker preconditions**: none beyond establishing a normal peer connection, which any node on the network can do.
- **Trigger**: sending a single well-formed (but unauthenticated) `PerasCert` CBOR message over the Peras certificate diffusion miniprotocol.
- **Existing mitigations**: none at the validation layer; the only guard is the immutability staleness check, which does not prevent targeting volatile blocks.
- **Likelihood**: High — the miniprotocol is wired into the production node-to-node handler and the stub is the only deployed instance.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The BLS aggregate signature over the quorum of committee votes.
2. That the signing committee members are eligible (registered stake pool keys with sufficient stake).
3. That the total stake of the signing committee exceeds the quorum threshold (`perasQuorumStakeThreshold`).
4. That the certificate's `pcCertRound` is within the valid range relative to the current slot.

Until the real implementation is ready, the `hPerasCertDiffusionClient` handler should be disabled or gated behind a feature flag so that the stub is never reachable from untrusted peers in a production deployment. [7](#0-6) 

### Proof of Concept

**Deterministic reasoning (no live network required):**

1. Compile the node with the current codebase.
2. Establish a peer connection to a running node.
3. Send the following CBOR-encoded `PerasCert` over the Peras certificate diffusion miniprotocol:
   ```
   PerasCert { pcCertRound = <any round not yet in DB>, pcCertBoostedBlock = <hash of target block in volatile DB> }
   ```
4. Observe via tracing that `ChainSelectionForBoostedBlock` is emitted and chain selection runs for the target block.
5. If the target block is on a fork whose total weight (block count + 15) exceeds the current chain's weight, the node switches to that fork.

The stub at `SupportsPeras.hs:353–358` guarantees step 3 always passes validation, making steps 4–5 deterministically reachable by any peer. [8](#0-7) [9](#0-8)

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
