### Title
Degenerate `validatePerasCert` stub unconditionally accepts any inbound Peras certificate, enabling forged-cert-driven chain selection — (`Ouroboros/Consensus/Block/SupportsPeras.hs`, `ObjectPool/PerasCert.hs`, `NodeToNode.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a `validatePerasCert` that unconditionally returns `Right`, with no BLS aggregate-signature check, no quorum check, and no committee-eligibility check. This stub is wired directly into the live `hPerasCertDiffusionClient` handler for `NodeToNodeV_16`. Any peer that can negotiate that version can inject an arbitrary `PerasCert blk` — with any `pcBoostedBlock` — and the node will accept it, store it, and trigger `chainSelectionForBlock` for the boosted block if it is already in the VolatileDB.

---

### Finding Description

**Stub location** — `SupportsPeras.hs` lines 350–358:

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

The degenerate `PerasCert blk` data type (the one actually used on the wire) carries only `pcCertRound` and `pcCertBoostedBlock` — no signature field at all. [2](#0-1) 

**Production wiring** — `makePerasCertPoolWriterFromChainDB` passes this stub as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

This writer is registered as the live `hPerasCertDiffusionClient` handler in `NodeToNode.hs`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**`processCerts` logic** — because `validateCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every inbound cert is forwarded to `addCert` (i.e., `ChainDB.addPerasCertAsync`): [5](#0-4) 

**Chain-selection trigger** — `chainSelSync` for `ChainSelAddPerasCert` calls `chainSelectionForBlock` for the boosted block whenever it is present in the VolatileDB: [6](#0-5) 

**Note on the question's framing:** The question references `V1.PerasCert` / `fromPerasCert` in `Committee.hs`. Those are type-conversion helpers for a future BLS-backed cert type and are **not** in the production diffusion path. The actual wire type is the degenerate `PerasCert blk` (no signature field). The core vulnerability — the unconditional `Right` stub — is real regardless.

---

### Impact Explanation

An unprivileged peer that negotiates `NodeToNodeV_16` can:

1. Craft a `PerasCert blk` with an arbitrary `pcBoostedBlock` pointing to any block hash already in the target node's VolatileDB (received via normal BlockFetch).
2. Submit it via the object-diffusion protocol.
3. The cert bypasses all validation, is stored in the `PerasCertDB`, and triggers `chainSelectionForBlock` for the boosted block.
4. If the boosted block is on a competing fork, the node's chain selection re-evaluates that fork with the artificial Peras weight boost and may irreversibly switch to it.

This satisfies: **Critical — consensus safety failure / bypass of certificate validation that enables unauthorized certificate acceptance and divergent chain selection**.

---

### Likelihood Explanation

- The `hPerasCertDiffusionClient` handler is unconditionally registered for any peer that negotiates `NodeToNodeV_16`. No feature flag, no era gate, no operator opt-in is required.
- The attacker needs only a valid TCP connection to the node and knowledge of a block hash in the VolatileDB (obtainable via ChainSync headers).
- The exploit requires no stake, no keys, and no privileged access.

---

### Recommendation

Replace the stub with real validation before `NodeToNodeV_16` is enabled on any network where Peras weight influences chain selection. At minimum, gate the `validatePerasCert` call so that it returns `Left PerasValidationErr` (rejecting all certs) until the BLS aggregate-signature verification and committee-eligibility checks tracked in [cardano-peras#120](https://github.com/tweag/cardano-peras/issues/120) are implemented. Alternatively, disable the `hPerasCertDiffusionClient` handler entirely (return a no-op writer) until the full validation stack is in place.

---

### Proof of Concept

Using `io-sim` or a local two-node testnet with `NodeToNodeV_16`:

```haskell
-- 1. Obtain a block hash already in the peer's VolatileDB via ChainSync.
let forgedCert = PerasCert
      { pcCertRound      = PerasRoundNo 1
      , pcCertBoostedBlock = BlockPoint someSlot someHashFromVolatileDB
      }

-- 2. Submit via the object-diffusion inbound path (peer acts as outbound/server).
--    processCerts calls (validatePerasCert mkPerasParams forgedCert)
--    => Right (ValidatedPerasCert { vpcCert = forgedCert, vpcCertBoost = ... })
--    => ChainDB.addPerasCertAsync cert

-- 3. Observe: chainSelSync fires chainSelectionForBlock for someHashFromVolatileDB
--    with the artificial Peras weight boost, potentially switching the node's chain.
```

The `processCerts` function will always take the `([], validatedCerts)` branch for any well-formed `PerasCert blk`, because `validatePerasCert` never inspects the cert contents. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L122-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-531)
```haskell
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
```
