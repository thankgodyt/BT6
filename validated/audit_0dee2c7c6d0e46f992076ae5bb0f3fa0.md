### Title
Unconditional Peras Certificate Acceptance Enables Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`) calls a `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or quorum verification. Any unprivileged peer can send a crafted `PerasCert` message that will be accepted, stored in the `PerasCertDB`, and used to boost an adversarial fork block during chain selection, potentially causing an honest node to switch away from the canonical chain.

---

### Finding Description

**Root cause — stub validation always accepts:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for all inbound certificates. The only deployed instance (the "degenerate instance for all blks") unconditionally returns `Right`:

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

No signature, no quorum proof, no committee membership check, no round-number sanity check — every certificate is accepted. The `PerasCert` data type itself carries only a round number and a block point; it contains no cryptographic material whatsoever:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

**Attacker-controlled entry path — object diffusion mini-protocol:**

The production pool writer `makePerasCertPoolWriterFromChainDB` is the live network-facing handler for inbound Peras certificates. It calls `validatePerasCert mkPerasParams` directly:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` then passes every certificate that clears this non-existent gate to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain selection consequence:**

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block: [5](#0-4) 

Chain selection computes `WeightedSelectView` as `wsvTotalWeight = blockNo + weightBoost`. A fake certificate injects `perasWeight params = PerasWeight 15` of boost onto any block the attacker names: [6](#0-5) 

With the default `perasWeight = PerasWeight 15`, a single forged certificate makes a fork block appear 15 block-lengths heavier than it actually is, which is sufficient to cause the node to prefer a fork that is up to 15 blocks shorter than the honest chain.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` naming any block in the node's VolatileDB as the boosted block. The node will accept it unconditionally, store it, and re-run chain selection. If the boosted block is on a fork, the node may switch to that fork, abandoning the canonical chain. This is a **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain** — matching the High impact tier.

---

### Likelihood Explanation

The entry path is the live object-diffusion mini-protocol, reachable from any peer connection. The stub is the only deployed instance of `validatePerasCert`. No configuration, key material, or stake is required. Any peer that can establish a connection and send a well-formed CBOR-encoded `PerasCert` message triggers the bug.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate BLS signature over the claimed quorum of committee votes, check that the signers are eligible committee members for the stated round, and confirm that their combined stake meets `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
2. **Do not ship the stub instance** (`instance StandardHash blk => BlockSupportsPeras blk`) in any build that connects to untrusted peers. Gate it behind a compile-time flag or replace it with a proper per-era instance before enabling the object-diffusion mini-protocol.
3. **Add a round-number bounds check** in `processCerts` / `chainSelSync` to reject certificates whose `pcCertRound` is implausibly far in the future relative to the current slot.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect a malicious peer to an honest node via the object-diffusion mini-protocol.
2. Identify a fork block `B_fork` present in the honest node's VolatileDB (e.g., obtained via `BlockFetch`) that is on a chain 14 blocks shorter than the current selection.
3. Craft a `PerasCert { pcCertRound = <any fresh round>, pcCertBoostedBlock = blockPoint B_fork }` and send it to the honest node.
4. Because `validatePerasCert` returns `Right` unconditionally, the certificate is accepted and stored. `chainSelSync` triggers `chainSelectionForBlock` for `B_fork`.
5. The `WeightedSelectView` for the fork now has `wsvTotalWeight = blockNo(B_fork) + 15`, which exceeds the honest chain's `wsvTotalWeight = blockNo(honest_tip) + 0` (since `15 > 14`).
6. The honest node switches to the adversarial fork. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-177)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
