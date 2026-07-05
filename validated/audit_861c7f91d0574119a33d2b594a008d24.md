### Title
Peras Certificate Validation Bypass via Unconditional `validatePerasCert` Stub Accepts Any Peer-Supplied Certificate - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that always returns `Right`, accepting every inbound `PerasCert` as fully valid regardless of its cryptographic content. Because this function is wired directly into the production node-to-node Peras certificate diffusion inbound handler, any unprivileged peer can inject a crafted `PerasCert` boosting an arbitrary block point, causing the receiving node to apply a `perasWeight = 15` chain-selection boost to a block the attacker chooses.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate's cryptographic proof before it is stored and used in chain selection. The universal instance (covering all block types) implements this gate as a no-op:

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

This stub is called by `processCerts` inside `makePerasCertPoolWriterFromChainDB`, which is the `ObjectPoolWriter` used by the live inbound Peras certificate diffusion handler:

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

This writer is registered directly in the production node-to-node handler setup:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

`processCerts` validates each certificate using the supplied function and, if all pass, adds them to the ChainDB via `addPerasCertAsync`. Because `validatePerasCert` always returns `Right`, every certificate from every peer passes validation unconditionally. [4](#0-3) 

The `PerasCert` data type carries only a `pcCertRound :: PerasRoundNo` and a `pcCertBoostedBlock :: Point blk` — both fully attacker-controlled over the wire:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [5](#0-4) 

The resulting `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, where `perasWeight = 15` in `mkPerasParams`, which is the weight applied to chain selection for the boosted block. [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` naming any `Point blk` as `pcCertBoostedBlock`. The receiving node will store it as a `ValidatedPerasCert` with full `perasWeight = 15` boost and apply it during chain selection. This allows the attacker to make an honest node prefer a non-canonical or adversarially chosen chain fragment over the honest chain, violating Peras chain-selection safety. The impact matches: **Bypass of Peras certificate checks that enables unauthorized certificate acceptance**, and **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The attack requires only a standard node-to-node connection and the ability to send a single crafted `PerasCert` message over the `PerasCertDiffusion` mini-protocol. No keys, stake, or special privileges are needed. The Peras certificate diffusion protocol is active in the production handler wiring. Likelihood is **High** given the zero-barrier entry path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real cryptographic check that verifies:
1. The certificate carries a valid aggregate BLS/committee signature over `(pcCertRound, pcCertBoostedBlock)`.
2. The signing committee members collectively hold stake above the `perasQuorumStakeThreshold`.
3. The `pcCertBoostedBlock` refers to a block that actually exists in the node's chain.

Until real validation is implemented, the inbound Peras certificate diffusion handler should be disabled or gated behind a feature flag so that no peer-supplied certificates are accepted.

---

### Proof of Concept

1. Connect to a target node via the node-to-node protocol with Peras certificate diffusion enabled.
2. Send a `PerasCert` message with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of attacker-chosen block>`.
3. The node calls `processCerts` → `validatePerasCert mkPerasParams cert` → unconditionally returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = 15 })`.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. Chain selection now applies a weight-15 boost to the attacker-specified block, potentially causing the node to switch to or prefer a non-canonical chain.

The root cause is identical in structure to the external report: just as `VaderPoolV2.mintSynth` accepted an arbitrary `from` address without enforcing the actual caller, `validatePerasCert` accepts an arbitrary certificate without enforcing any cryptographic proof of origin or quorum. [7](#0-6) [8](#0-7) [3](#0-2)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
