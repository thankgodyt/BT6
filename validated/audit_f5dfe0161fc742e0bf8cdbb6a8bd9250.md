### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation in the degenerate `BlockSupportsPeras` instance unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Because this function is wired directly into the live `hPerasCertDiffusionClient` handler, any unprivileged peer can inject an arbitrary `PerasCert` (for any round, pointing at any block) and have it accepted, stored, and used to boost that block's weight in chain selection.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The sole concrete instance (marked `-- TODO: degenerate instance for all blks to get things to compile`) implements this gate as an unconditional pass-through:

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

No signature is verified, no round number is checked, no boosted-block validity is confirmed, and no quorum proof is required. The `PerasValidationErr` data type is itself a stub with a single opaque constructor, making it structurally impossible to express any real error. [2](#0-1) 

This stub is the function passed as `validateCert` inside `makePerasCertPoolWriterFromChainDB`, the production pool writer used by the live node-to-node handler:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
...
(void . ChainDB.addPerasCertAsync chainDB)
``` [3](#0-2) 

`processCerts` calls `validateCert` on every new certificate and, when all pass (which they always do), immediately forwards them to `addCert`: [4](#0-3) 

The pool writer is installed as `hPerasCertDiffusionClient` in the live node-to-node handler bundle:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

The `perasCertDiffusionProtocol` is included in the full `initiatorAndResponder` bundle, making it reachable from any connected peer: [6](#0-5) 

---

### Impact Explanation

Once a crafted `PerasCert` is accepted and stored via `addPerasCertAsync`, it is used by chain selection to apply a weight boost (`vpcCertBoost = perasWeight params`) to the attacker-chosen block. The `getPerasWeightSnapshot` and `getLatestPerasCertSeen` APIs expose this boosted state to the chain-selection logic: [7](#0-6) 

An attacker can therefore:
1. Craft a `PerasCert` naming any block on a minority fork as the boosted block.
2. Send it over the `PerasCertDiffusion` miniprotocol.
3. The receiving node accepts it without any check, stores it, and re-evaluates chain selection with the artificial weight boost applied to the attacker's chosen block.
4. If the boost is sufficient to tip the chain-selection preference, the honest node switches to the attacker's fork, diverging from the canonical chain.

This is a direct bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The `hPerasCertDiffusionClient` handler is wired into the production node-to-node protocol bundle and is active whenever the `perasCertDiffusionProtocol` is negotiated. No special privileges, keys, or stake are required — any peer that can establish a node-to-node connection can send a `PerasCert` message. The exploit requires only constructing a valid CBOR-encoded `PerasCert` record (two fields: a round number and a block point), both of which are fully attacker-controlled.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
- Verifies the aggregate BLS signature over the election identifier and candidate block.
- Confirms the certificate's round number is within the valid window.
- Checks that the boosted block point exists and is on a known chain.
- Validates that the quorum threshold was actually met by the signers.

Until real validation is implemented, the `hPerasCertDiffusionClient` handler should not be exposed to untrusted peers (e.g., gate it behind a feature flag that is disabled by default in production builds).

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a two-node private testnet with Peras cert diffusion enabled.
2. On the attacker node, construct a `PerasCert` CBOR payload:
   ```
   -- Round 999, pointing at the genesis block (or any minority-fork block point)
   PerasCert { pcCertRound = 999, pcCertBoostedBlock = <target block point> }
   ```
3. Send this payload via the `PerasCertDiffusion` miniprotocol to the honest node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..}` unconditionally. [8](#0-7) 
5. The cert is stored via `addPerasCertAsync chainDB cert`.
6. Chain selection re-runs with `perasWeight` boost applied to the attacker-chosen block.
7. Observe via `getLatestPerasCertSeen` that the fake cert is now the node's latest seen certificate, and that chain selection has been influenced accordingly.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-348)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1263)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
