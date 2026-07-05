### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inject Arbitrary Chain-Weight Boosts - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound `PerasCert` without performing any cryptographic or structural verification. Any peer that speaks the Peras certificate diffusion mini-protocol can inject a crafted certificate that boosts an arbitrary block, triggering chain selection and potentially causing the node to switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that converts an untrusted wire `PerasCert` into a `ValidatedPerasCert`. The only deployed instance is a catch-all stub:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This function always returns `Right`, meaning **every** certificate received from any peer is immediately stamped as `ValidatedPerasCert` with a full weight boost, regardless of its content.

The inbound diffusion path wires this directly into the production node-to-node handler:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` then calls `addPerasCertAsync` on the ChainDB for every certificate that passes this non-validation: [4](#0-3) 

The ChainDB API documents the consequence explicitly:

```haskell
, addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [5](#0-4) 

The `ValidatedPerasCert` type carries a `vpcCertBoost :: PerasWeight` field that is used by `getWeightSnapshot` in the `PerasCertDB` to influence chain selection comparisons: [6](#0-5) 

Additionally, the `getLatestCertSeen` field in `PerasCertDB` is a precondition for voting in subsequent rounds, meaning a fake certificate also corrupts the node's voting eligibility state: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as `pcCertBoostedBlock`. Because `validatePerasCert` always returns `Right`, the certificate is accepted as `ValidatedPerasCert` with full `perasWeight`. This weight boost is then used during chain selection to make the targeted block's chain appear heavier than the honest chain, potentially causing the node to switch to a non-canonical fork. The attack also poisons `getLatestCertSeen`, which gates whether the node is allowed to vote in subsequent Peras rounds.

This maps to the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol handler is wired unconditionally into the production `NodeToNode` handler record. Any peer that negotiates a protocol version enabling the `hPerasCertDiffusionClient` handler can send crafted certificates. No stake, key material, or privileged access is required. The attacker only needs a network connection to the target node.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature over the certificate's `(electionId, boostedBlock)` payload against the aggregate public key derived from the claimed voter set and the epoch's stake distribution.
2. Checks that the voter set meets the quorum threshold.
3. Verifies that `pcCertRound` falls within the expected window relative to the current chain tip.

Until the real implementation is ready, the inbound certificate diffusion handler should be disabled or gated behind a feature flag so that no peer-supplied certificate can reach `addPerasCertAsync`.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node and negotiates a protocol version that activates `hPerasCertDiffusionClient`.
2. Attacker sends a single `PerasCert` message via the ObjectDiffusion protocol with `pcCertBoostedBlock` set to the hash of any block the attacker wishes to boost (e.g., a block on a sparse adversarial fork).
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which unconditionally returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. `addPerasCertAsync chainDB` is called with the fake `ValidatedPerasCert`.
5. Chain selection re-runs; the targeted block's chain now carries the full Peras weight boost.
6. If the boosted chain is otherwise competitive (e.g., same length), the node switches to it.

The root cause — `validatePerasCert` always returning `Right` — is at: [1](#0-0) 

The production wiring that makes it reachable from any peer is at: [2](#0-1)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-72)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
  -- (at origin).
```
