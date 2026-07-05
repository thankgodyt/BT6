### Title
Peras Certificate Validation Uses Hardcoded `mkPerasParams` Instead of Actual Node Configuration, Accepting All Inbound Certificates Without Cryptographic Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` call `validatePerasCert mkPerasParams` — passing a hardcoded global default (`mkPerasParams`) instead of the actual node's Peras configuration. This is the direct analog of the reported "wrong parameter" vulnerability class. Compounding this, the `validatePerasCert` implementation for the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right`, meaning every inbound Peras certificate from any peer is accepted without any cryptographic or semantic check and immediately used to boost blocks in chain selection.

---

### Finding Description

**Root cause — wrong parameter used (analog to H06):**

In `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`, the `validatePerasCert` call receives `mkPerasParams` — a hardcoded compile-time default — rather than the actual Peras configuration that should be threaded from the node's `TopLevelConfig` or `ChainDB`:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [1](#0-0) [2](#0-1) 

**Root cause — stub always returns `Right`:**

The universal `BlockSupportsPeras` instance's `validatePerasCert` ignores all certificate content and unconditionally accepts every certificate, deriving the boost weight solely from the (already wrong) hardcoded params:

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
``` [3](#0-2) 

**Processing pipeline:**

`processCerts` validates each inbound certificate via the supplied `validateCert` callback. Because that callback always returns `Right`, every certificate passes and is added to the database (or ChainDB), triggering chain selection with the boosted block: [4](#0-3) 

The ChainDB path then triggers `chainSelectionForBlock` for the boosted block: [5](#0-4) 

---

### Impact Explanation

**High — Chain selection manipulation via crafted Peras certificates.**

An unprivileged peer can craft a `PerasCert` pointing to any block hash and any round number. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to apply a `perasWeight` boost to the targeted block in chain selection. By boosting a block on a non-canonical fork, an adversary can cause an honest node to prefer that fork over the honest chain, violating chain selection safety beyond the intended Ouroboros security assumptions.

Additionally, because `mkPerasParams` is used instead of the actual node configuration, the boost weight (`perasWeight`) applied to every accepted certificate is the hardcoded default value rather than the operator-configured value. Even if the stub were replaced with real validation, the wrong parameters would still be used, potentially allowing certificates that should be rejected (e.g., those failing quorum threshold checks under the real config) to pass.

---

### Likelihood Explanation

**High.** The inbound certificate processing path (`makePerasCertPoolWriterFromChainDB` → `processCerts`) is wired into the production diffusion layer and is reachable by any connected peer that sends a `PerasCert` object via the Peras object diffusion mini-protocol. No special privileges, keys, or stake are required. The attacker only needs to be a connected peer and send a well-formed (but semantically invalid) `PerasCert` CBOR message.

---

### Recommendation

1. **Immediate:** Replace the `validatePerasCert` stub with a real implementation that verifies the aggregate BLS signature, checks quorum thresholds, and validates the boosted block reference against the known chain.
2. **Wrong parameter fix (direct analog to H06):** Thread the actual node Peras configuration (from `TopLevelConfig` or `ChainDB`) into `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` as an explicit parameter, replacing the hardcoded `mkPerasParams`.
3. Until (1) is complete, consider gating the Peras certificate diffusion path behind a feature flag that is disabled by default in production builds.

---

### Proof of Concept

1. Connect to a node as an unprivileged peer via the Peras certificate object diffusion mini-protocol.
2. Construct a `PerasCert` (serialized per the `ToCBOR` instance) with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of a block on a competing fork>`.
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=15}` unconditionally.
5. The certificate is added to the `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
6. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block, applying a weight of 15 to the targeted fork.
7. If the fork's boosted weight exceeds the honest chain's weight, the node switches to the adversarial fork. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
