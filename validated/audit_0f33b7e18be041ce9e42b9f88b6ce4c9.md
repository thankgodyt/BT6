### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Forge Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum verification. This stub is wired directly into the network-facing Peras certificate ingest pipeline. Any unprivileged peer can send a crafted `PerasCert` pointing to any block in the victim's VolatileDB, have it accepted as "validated," and trigger chain selection with a `perasWeight = 15`-block boost for that block, causing the node to prefer a non-canonical adversarial fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate's aggregate BLS signature, quorum membership, and round validity before the certificate is admitted to the `PerasCertDB` and used to influence chain selection.

The sole production instance of this typeclass is the degenerate catch-all instance at: [1](#0-0) 

Its `validatePerasCert` body is: [2](#0-1) 

The function ignores the certificate entirely and returns `Right` unconditionally. No signature is checked, no quorum is verified, no round-number bounds are enforced.

This stub is called directly in the production network ingest path. `makePerasCertPoolWriterFromChainDB` — the writer used for all peer-sourced certificates — passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`: [3](#0-2) 

`processCerts` treats a `Right` result as proof of validity and immediately forwards the certificate to `ChainDB.addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. The chain-selection handler then adds the certificate to the `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

The boost applied is `perasWeight = 15` (15 extra blocks of chain weight), as set in `mkPerasParams`: [6](#0-5) 

The `PerasCert` wire type carries only a round number and a boosted block point — no signature field — so a crafted certificate requires no cryptographic material at all: [7](#0-6) 

The concrete on-wire `PerasCert` type in `Peras.Cert.V1` does carry a BLS aggregate signature, but the degenerate instance used in the pipeline never inspects it.

---

### Impact Explanation

An unprivileged peer can send a single crafted `PerasCert` message that names any block in the victim's VolatileDB as the "boosted" block. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to add 15 blocks of artificial weight to the named block during chain selection. If the attacker's target block is on a competing fork within `k` blocks of the current tip, the victim node will switch to that fork, accepting a non-canonical or adversarially-constructed chain. This is a direct chain-selection safety failure triggered by a single unauthenticated network message.

---

### Likelihood Explanation

The attack requires only a peer connection and knowledge of a block hash present in the victim's VolatileDB (obtainable via normal ChainSync). No keys, stake, or prior chain state are needed. The degenerate instance is the only instance in scope for all block types, so every node running this code is affected. Likelihood is high.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed quorum members.
2. Checks that the claimed voters collectively hold stake above the quorum threshold.
3. Validates that the certificate's round number is within the permitted window relative to the current chain tip.

Until the full implementation is ready, the stub should at minimum reject all inbound certificates from peers (return `Left PerasValidationErr` unconditionally) rather than accept them all, so that the network-facing path is safe even in the incomplete state. The same audit should be applied to `validatePerasVote`, which also ignores the `_params` argument and performs no signature check.

---

### Proof of Concept

```
Attacker node  ──[ObjectDiffusion: PerasCert msg]──►  Victim node
                                                          │
  PerasCert {                                             │
    pcCertRound    = <any round>,                         │
    pcCertBoostedBlock = <hash of block on adv. fork>     │
  }                                                       │
                                                          ▼
                                              processCerts calls
                                              validatePerasCert mkPerasParams cert
                                                          │
                                              Returns Right unconditionally
                                                          │
                                              addPerasCertAsync enqueues cert
                                                          │
                                              chainSelSync: ChainSelAddPerasCert
                                              adds +15 weight to adversarial block
                                                          │
                                              chainSelectionForBlock switches
                                              victim to adversarial fork
```

The attacker needs only a valid peer connection. The `PerasCert` wire format requires only a round number and a block point; no BLS key material is needed because `validatePerasCert` never inspects the certificate content.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
