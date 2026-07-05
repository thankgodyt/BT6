### Title
Unauthenticated Peras Certificate Injection Enables Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The only deployed `BlockSupportsPeras` instance provides a degenerate `validatePerasCert` that unconditionally accepts every inbound certificate. Because the Peras certificate diffusion mini-protocol (`PerasCertDiffusion`) is wired into the production node-to-node stack as of `NodeToNodeV_16`, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block's chain weight, potentially causing the receiving node to prefer a non-canonical adversarial chain over the honest chain.

---

### Finding Description

**Root cause — always-accept certificate validation stub**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates. The only deployed instance is an explicit placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params  -- always 15
        }
```

This stub returns `Right` for every certificate regardless of content, round number, boosted block, or any cryptographic proof. [1](#0-0) 

**Reachable entry path — production mini-protocol handler**

`makePerasCertPoolWriterFromChainDB` is the production pool writer used by the `hPerasCertDiffusionClient` handler in `NodeToNode.hs`. It passes `validatePerasCert mkPerasParams` directly as the validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

This writer is wired directly into the production node-to-node application:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

The `PerasCertDiffusion` mini-protocol is registered as a full `InitiatorAndResponder` protocol in `NodeToNodeV_16`: [4](#0-3) 

**Chain selection impact path**

`processCerts` accepts every certificate (since `validatePerasCert` always returns `Right`) and calls `ChainDB.addPerasCertAsync`. The ChainDB background thread processes it via `chainSelSync`, which triggers chain selection for the boosted block:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  -- Trigger chain selection for the boosted block.
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

Chain selection uses `preferAnchoredCandidate` with the `PerasWeightSnapshot` (now containing the injected boost). When Peras weights are non-empty, comparison uses `weightedSelectView`, which computes total weight as `blockNo + perasWeight`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

With `perasWeight = 15` (from `mkPerasParams`), an adversarial chain that is within 15 blocks of the honest chain tip can be made to appear heavier after a single injected certificate. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer connecting via `NodeToNodeV_16` can send a crafted `PerasCert` naming any block in the target node's VolatileDB as the boosted block. The certificate bypasses all validation, is stored in the `PerasCertDB`, and causes the `PerasWeightSnapshot` to assign a weight boost of 15 to the targeted block's chain. Chain selection then uses this snapshot, and if the adversarial fork is within 15 blocks of the honest tip, the node will switch to it. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of Praos/Peras.

---

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is unconditionally enabled for every peer connecting with `NodeToNodeV_16` — no feature flag, no opt-in. The attacker needs only a standard peer connection and knowledge of a block hash in the target's VolatileDB (trivially obtained via ChainSync). No stake, keys, or operator access is required. The attack is repeatable: one certificate per round number is accepted, but an attacker can use different round numbers to inject multiple boosts.

---

### Recommendation

1. **Short term:** Gate the `PerasCertDiffusion` mini-protocol behind a disabled-by-default feature flag until `validatePerasCert` is replaced with real cryptographic validation (BLS aggregate signature verification + VRF eligibility checks as implemented in `WFALS`/`EveryoneVotes`).
2. **Long term:** Replace the degenerate `instance StandardHash blk => BlockSupportsPeras blk` with a proper per-era instance that performs full committee membership, VRF eligibility, and aggregate signature verification before any certificate is admitted to the `PerasCertDB` or triggers chain selection.

---

### Proof of Concept

1. Connect to a target node using `NodeToNodeV_16` (the `PerasCertDiffusion` protocol is active).
2. Learn the hash of a block on an adversarial fork via ChainSync — call it `advBlockPoint`.
3. Craft a `PerasCert { pcCertRound = R, pcCertBoostedBlock = advBlockPoint }` for any unused round `R`.
4. Send the certificate via the `PerasCertDiffusion` inbound channel.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → always returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
6. `ChainDB.addPerasCertAsync` enqueues the certificate; `chainSelSync` triggers `chainSelectionForBlock` for `advBlockPoint`.
7. `preferAnchoredCandidate` now computes the adversarial chain's total weight as `blockNo(advTip) + 15`. If this exceeds the honest chain's `blockNo(honestTip) + 0`, the node switches to the adversarial fork.
8. Repeat with a new round number to re-boost after the honest chain grows.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1265)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
        , perasVoteDiffusionProtocol =
            ( InitiatorAndResponderProtocol
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-61)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
