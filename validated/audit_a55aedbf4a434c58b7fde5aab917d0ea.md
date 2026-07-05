### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts All Certificates, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that **always returns `Right`** (success) without performing any cryptographic or semantic checks. Because this function is wired directly into the production Peras certificate ingestion pipeline (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can send a crafted `PerasCert` for an arbitrary block, have it accepted as valid, and trigger chain selection with artificial weight boosting — causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance (the only instance in the codebase, used for all block types) implements this as:

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

This unconditionally returns `Right` — no quorum check, no committee membership check, no cryptographic signature verification, no round-number sanity check. The `PerasValidationErr` data type is also a stub with a single constructor and no payload, making it structurally impossible to express any real error. [1](#0-0) 

This function is called directly in the **production** certificate pool writer:

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

`processCerts` calls `validateCert` on each inbound certificate and only rejects if it returns `Left`. Since `validatePerasCert` never returns `Left`, every certificate from every peer passes: [3](#0-2) 

Once accepted, the certificate is added to the `PerasCertDB` and, if it boosts a block not on the current chain, triggers chain selection for that block: [4](#0-3) 

The `PerasCert` structure contains only a round number and a boosted block point — both fully attacker-controlled: [5](#0-4) 

The weight assigned to the boosted block (`vpcCertBoost = perasWeight params`) is drawn from the node's own `PerasParams`, so the attacker gets the full protocol-defined boost applied to their chosen block.

---

### Impact Explanation

Peras certificates exist to boost the chain-selection weight of a specific block, allowing a chain containing that block to be preferred over a longer chain without a certificate. By bypassing all certificate validation, an unprivileged peer can:

1. Craft a `PerasCert` pointing to any block in the VolatileDB (or any block the node has received).
2. Send it via the Peras certificate mini-protocol.
3. Have it unconditionally accepted and stored.
4. Trigger chain selection for the boosted block, causing the node to potentially switch to a non-canonical chain that it would otherwise reject.

This is a **bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain selection manipulation**, matching the "Critical" impact tier: *Bypass of PBFT/Praos/TPraos/Peras voting or certificate checks that enables unauthorized certificate acceptance.*

---

### Likelihood Explanation

The Peras certificate mini-protocol is a public, peer-facing interface. Any node that connects as a peer can send `PerasCert` objects. No stake, no keys, and no prior authentication are required. The attack requires only:
- Knowing the hash of a block in the target node's VolatileDB (trivially obtained via ChainSync).
- Sending a single well-formed `PerasCert` message.

The `processCerts` pipeline is already wired into the production `ChainDB` path via `makePerasCertPoolWriterFromChainDB`. The likelihood is **High** for any deployment where the Peras certificate diffusion protocol is active.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The certificate carries a valid aggregate BLS/committee signature from a quorum of eligible committee members for the claimed round.
2. The round number is within the acceptable window relative to the current chain tip.
3. The boosted block point corresponds to a block that was actually eligible to be boosted in that round.

Until real validation is implemented, the certificate ingestion pipeline should not be connected to the production `ChainDB` chain selection path. [6](#0-5) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to the target node and the Peras certificate object-diffusion mini-protocol is established.
2. Peer sends a `PerasCert` with:
   - `pcCertRound = <any round number>`
   - `pcCertBoostedBlock = <point of a block on a weaker fork in the target's VolatileDB>`
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` → unconditionally returns `Right ValidatedPerasCert{...}`.
4. `ChainDB.addPerasCertAsync chainDB` stores the cert.
5. `chainSelSync` handles `ChainSelAddPerasCert`, finds the boosted block in the VolatileDB, and calls `chainSelectionForBlock` for it.
6. Chain selection now evaluates the boosted block's chain with the artificial weight boost, potentially switching the node's selection to the attacker-chosen fork. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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
