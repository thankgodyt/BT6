### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can therefore inject an arbitrary `PerasCert` via the live `PerasCertDiffusion` mini-protocol. The certificate is accepted, stored in the `PerasCertDB`, and — if the boosted block is present in the VolatileDB — immediately triggers `chainSelectionForBlock`, which can cause the honest node to switch away from the canonical chain onto the adversary's fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

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

This is the **only** `BlockSupportsPeras` instance in the codebase (the comment "degenerate instance for all blks" confirms it is the universal fallback). No signature, committee membership, round-number range, or boosted-block validity check is performed.

**Inbound path — the mini-protocol is live for every peer:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` directly as the validation callback for all inbound certificates received over the `PerasCertDiffusion` mini-protocol:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

The handler is registered unconditionally for every node-to-node connection:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [3](#0-2) 

**Chain-selection side-effect — accepted certificate triggers fork switch:**

`chainSelSync` for `ChainSelAddPerasCert` adds the certificate to the `PerasCertDB` and, when the boosted block is present in the VolatileDB, immediately calls `chainSelectionForBlock`:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection now uses Peras weights (confirmed by the CHANGELOG: *"the candidate fragment is now selected based on its Peras weight, instead of its length"*). The weight boost `vpcCertBoost = perasWeight params` is assigned to every accepted certificate, so a crafted certificate for a block on an adversarial fork can make that fork heavier than the honest chain, causing a switch. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` that names any block hash in the node's VolatileDB as the "boosted block." Because `validatePerasCert` never rejects anything, the certificate is stored and the Peras weight snapshot is updated. Chain selection then re-evaluates the candidate containing that block with an inflated weight. If the adversary has pre-seeded the VolatileDB with a fork block (via normal BlockFetch), the honest node can be made to switch to the adversary's non-canonical chain. This is a **chain selection safety failure** triggered by a single crafted protocol message from an unprivileged peer — matching the "High/Critical" impact tier: *bypass of Peras certificate checks enabling unauthorized certificate acceptance* and *chain selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain*.

---

### Likelihood Explanation

The `PerasCertDiffusion` client handler is registered for every node-to-node connection with no Peras-enabled guard. Any peer that can establish a standard connection can send certificates. The attack requires only that the adversary (1) connect to the target node, (2) deliver a fork block via BlockFetch so it lands in the VolatileDB, and (3) send a `PerasCert` naming that block. No keys, stake, or special privileges are needed. Likelihood is **High** for any deployment where Peras is enabled (private testnet or future mainnet rollout).

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the `PerasCertDiffusion` mini-protocol is enabled in any environment where chain selection uses Peras weights. At minimum, the validation must verify:

1. The certificate's cryptographic signature against the committee's public keys.
2. That the voter set meets the quorum threshold for the claimed round.
3. That the boosted block's slot falls within the valid range for the certificate's round number.
4. That the certificate round number is not in the future relative to the node's current ledger state.

Until real validation is implemented, the `PerasCertDiffusion` inbound handler should be disabled (or made a no-op) when Peras is not fully activated, preventing unauthenticated certificates from reaching `chainSelectionForBlock`.

---

### Proof of Concept

**Private-testnet sequence (Peras enabled):**

1. Adversary connects to the honest node via the standard node-to-node protocol.
2. Adversary sends a valid-looking block `B_adv` on a fork via BlockFetch; the node stores it in the VolatileDB.
3. Adversary sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B_adv) }` over the `PerasCertDiffusion` channel.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` unconditionally. [6](#0-5) 
5. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`. [7](#0-6) 
6. `chainSelSync` finds `B_adv` in the VolatileDB and calls `chainSelectionForBlock`.
7. Chain selection computes the weight of the adversarial fork including the Peras boost; if it exceeds the honest chain's weight, the node switches to the adversarial fork — accepting an invalid chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
