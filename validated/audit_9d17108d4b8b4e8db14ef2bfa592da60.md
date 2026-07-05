### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the only instance in the codebase, used for all block types — implements `validatePerasCert` as an unconditional `Right`, accepting every inbound certificate without any cryptographic, quorum, or committee check. Any unprivileged peer can send a crafted `PerasCert` over the live `PerasCertDiffusion` mini-protocol, have it accepted as valid, stored in the `PerasCertDB`, and trigger chain selection for an attacker-chosen block, potentially causing the node to switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase, applied universally via `instance StandardHash blk => BlockSupportsPeras blk`. No signature, no quorum proof, no committee membership check is performed. Every certificate presented is stamped `ValidatedPerasCert`.

**Production inbound path — `makePerasCertPoolWriterFromChainDB`:** [2](#0-1) 

The production writer wires `validatePerasCert mkPerasParams` directly as the validator and calls `ChainDB.addPerasCertAsync` for every certificate that passes it.

**Network entry point — `hPerasCertDiffusionClient` in `NodeToNode.hs`:** [3](#0-2) 

This handler is invoked for every connected peer over the live `PerasCertDiffusion` mini-protocol. It calls `makePerasCertPoolWriterFromChainDB`, which uses the stub validator above.

**Chain selection consequence — `chainSelSync` for `ChainSelAddPerasCert`:** [4](#0-3) 

After the certificate is stored in the `PerasCertDB`, if the boosted block is present in the `VolatileDB`, `chainSelectionForBlock` is called for it. The boosted block's chain fragment receives a `perasWeight` boost in `WeightedSelectView`, which can make it preferred over the current selection.

**Contrast with votes — votes are correctly rejected in production:** [5](#0-4) 

The vote diffusion handler explicitly passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution, and the comment acknowledges this causes all votes to be rejected. No equivalent safeguard exists for certificates — `validatePerasCert` ignores the stake distribution entirely and always returns `Right`.

---

### Impact Explanation

An unprivileged peer with a live `PerasCertDiffusion` connection can:

1. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` for any round `r` and any block point `p` that the target node has in its `VolatileDB`.
2. Send it over the mini-protocol. `validatePerasCert` returns `Right` unconditionally.
3. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` is called.
4. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block, adding `perasWeight` to its chain's `wsvWeightBoost`.
5. If the boosted fork's `wsvTotalWeight` now exceeds the current selection's, the node switches chains.

This is a **bypass of Peras certificate verification** that lets an unprivileged peer make an honest node prefer a non-canonical or attacker-chosen chain. It maps directly to the "Critical/High" impact category: bypass of certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

- **Attacker preconditions**: None beyond a standard peer connection. No keys, no stake, no privileged access required.
- **Trigger**: Send a single well-formed CBOR-encoded `PerasCert` over the `PerasCertDiffusion` channel.
- **Reachability**: The handler is wired into every node-to-node connection in `NodeToNode.hs`.
- **Likelihood**: High — the path is fully reachable from any connected peer with zero privilege.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that checks:
- Cryptographic aggregate signature over the election ID and vote candidate.
- Quorum: the certificate must represent votes from committee members whose combined stake exceeds the quorum threshold.
- Committee membership: each voter must be a valid committee member for the given round.

Until real validation is implemented, the `PerasCertDiffusion` inbound handler should be disabled or should unconditionally reject all inbound certificates (analogous to how the vote handler uses `pure (PerasVoteStakeDistr mempty)` to reject all votes).

---

### Proof of Concept

```
Attacker (any peer) connects via PerasCertDiffusion mini-protocol.

1. Identify a block hash H in the target node's VolatileDB that is on a
   minority fork F (e.g., obtained via ChainSync).

2. Craft:
     cert = PerasCert { pcCertRound    = <any round not yet in PerasCertDB>
                      , pcCertBoostedBlock = BlockPoint <slot> H }

3. Send cert over the PerasCertDiffusion channel.

4. processCerts calls validatePerasCert mkPerasParams cert
   => always returns Right (ValidatedPerasCert { vpcCert = cert
                                               , vpcCertBoost = perasWeight params })

5. addPerasCertAsync enqueues the cert.

6. chainSelSync (ChainSelAddPerasCert):
   - cert is not too old (slot >= immutable tip)
   - cert is not on current chain
   - boosted block H is in VolatileDB
   => chainSelectionForBlock is called for H

7. WeightedSelectView for fork F now has wsvWeightBoost += perasWeight.
   If wsvTotalWeight(F) > wsvTotalWeight(current), node switches to F.
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-409)
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
            version
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
