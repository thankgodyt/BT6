### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic, quorum, or committee-membership checks. This stub is wired directly into the production Peras cert-diffusion inbound handler (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject an arbitrary `PerasCert` pointing to any block, which the node will accept, store, and use to trigger a chain-selection fork switch via `addPerasCertAsync`, applying a Peras weight boost to the attacker's chosen block.

---

### Finding Description

**Root cause — `validatePerasCert` always succeeds:**

The catch-all `instance StandardHash blk => BlockSupportsPeras blk` (the only instance in the codebase) implements `validatePerasCert` as:

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

No signature is verified, no committee membership is checked, no quorum is confirmed. Every certificate, regardless of origin or content, is immediately wrapped in `ValidatedPerasCert` and returned as `Right`. [1](#0-0) 

**Production wiring — `makePerasCertPoolWriterFromChainDB` uses this stub:**

The production cert-diffusion pool writer passes `validatePerasCert mkPerasParams` directly as the validation callback:

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

**`processCerts` adds every cert that passes validation:**

`processCerts` calls `validateCert` on each inbound cert and, if all pass (which they always do), calls `addCert` for each one:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**`addPerasCertAsync` triggers chain selection:**

The `addCert` callback is `void . ChainDB.addPerasCertAsync chainDB`. The ChainDB API documents this as:

```haskell
addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [4](#0-3) 

**The Peras weight boost is non-trivial:**

`mkPerasParams` sets `perasWeight = PerasWeight 15`, meaning every injected certificate applies a weight boost of 15 to the attacker's chosen block, directly influencing chain selection. [5](#0-4) 

**Attacker-controlled entry path — Peras cert diffusion miniprotocol:**

The node-to-node handler wires `makePerasCertPoolWriterFromChainDB` into the live cert-diffusion inbound client. The `Codecs` record confirms `cPerasCertDiffusionCodec` is a live protocol, and `makePerasCertPoolWriterFromChainDB` is explicitly documented as the production path (as opposed to the test-only `makePerasCertPoolWriterFromCertDB`). [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block (including an adversarial fork tip). Because `validatePerasCert` unconditionally accepts it, the node stores it as a `ValidatedPerasCert` with a weight boost of 15 and immediately triggers `addPerasCertAsync`. This causes the ChainDB to re-evaluate chain selection, potentially switching to the attacker's preferred fork. This is a **chain-selection manipulation** bug: an honest node can be made to prefer a non-canonical or adversarially-chosen chain without the attacker holding any stake, keys, or operator privileges.

Impact category: **High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

The Peras cert-diffusion miniprotocol is a live node-to-node protocol. Any peer that can establish a connection to the node (i.e., any node on the network) can send a crafted `PerasCert` message. No keys, stake, or special access are required. The attacker only needs to know a valid `Point blk` (block hash + slot) for the block they wish to boost, which is publicly observable on-chain. The attack is therefore trivially executable by any network participant.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS/committee signature over the certificate's `(electionId, candidate)` pair.
2. Confirms that the set of signers constitutes a valid quorum (total stake ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. Checks that each signer is a registered committee member for the relevant round.

Until the full committee-selection plumbing is in place, the inbound cert-diffusion handler should reject all externally received certificates (returning `Left PerasValidationErr` unconditionally) rather than accepting them all. This mirrors the approach already taken for votes in `NodeToNode.hs`, where an empty stake distribution causes all votes to be rejected. [7](#0-6) 

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras cert-diffusion miniprotocol.
2. Observe the tip of an adversarial fork at slot `S` with hash `H` (publicly visible).
3. Craft a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint S H }` for any round `R`.
4. Send the cert via the `ObjectDiffusion` protocol's inbound channel.
5. The node calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
6. `processCerts` calls `addPerasCertAsync chainDB (WithArrivalTime now validatedCert)`.
7. ChainDB re-runs chain selection; the adversarial fork now has a weight boost of 15 applied, potentially causing the node to switch to it.

Expected outcome: the honest node's preferred chain tip changes to the attacker's chosen block, demonstrating unauthorized chain-selection manipulation via a fake Peras certificate with no cryptographic authorization. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L428-440)
```haskell
data Codecs blk addr e m bCS bSCS bBF bSBF bTX bPCD bPVD bKA bPS = Codecs
  { cChainSyncCodec :: Codec (ChainSync (Header blk) (Point blk) (Tip blk)) e m bCS
  , cChainSyncCodecSerialised ::
      Codec (ChainSync (SerialisedHeader blk) (Point blk) (Tip blk)) e m bSCS
  , cBlockFetchCodec :: Codec (BlockFetch blk (Point blk)) e m bBF
  , cBlockFetchCodecSerialised ::
      Codec (BlockFetch (Serialised blk) (Point blk)) e m bSBF
  , cTxSubmission2Codec :: Codec (TxSubmission2 (GenTxId blk) (GenTx blk)) e m bTX
  , cPerasCertDiffusionCodec :: Codec (PerasCertDiffusion blk) e m bPCD
  , cPerasVoteDiffusionCodec :: Codec (PerasVoteDiffusion blk) e m bPVD
  , cKeepAliveCodec :: Codec KeepAlive e m bKA
  , cPeerSharingCodec :: Codec (PeerSharing addr) e m bPS
  }
```
