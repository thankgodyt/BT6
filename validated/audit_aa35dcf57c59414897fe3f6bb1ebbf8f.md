### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance unconditionally returns `Right` for every inbound certificate, performing no cryptographic or structural validation. Because this is the only compiled instance, any unprivileged peer connected via the ObjectDiffusion mini-protocol can inject a crafted `PerasCert` pointing to an arbitrary block, have it accepted as valid, and cause the receiving node to apply a `perasWeight = 15` boost to that block during chain selection — potentially making the node prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` is explicitly marked as a "degenerate instance for all blks to get things to compile" (issue #73). Its `validatePerasCert` implementation is:

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

This stub is wired directly into the production inbound certificate handler `processCerts` via `makePerasCertPoolWriterFromChainDB`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` filters out certs already in the DB by round number, then calls `validateCert` on the remainder. Because `validatePerasCert` always returns `Right`, every novel-round certificate from any peer passes: [3](#0-2) 

The accepted certificate is then forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes it by adding the cert to `PerasCertDB` and calling `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection uses `WeightedSelectView.preferCandidate`, which compares `wsvTotalWeight` — the sum of block number and `wsvWeightBoost`. The boost is read from `PerasWeightSnapshot`, which is populated from the `PerasCertDB`. A fraudulent cert for a block on a minority fork adds `perasWeight = 15` to that fork's total weight, potentially causing `preferCandidate` to return `ShouldSwitch`: [5](#0-4) 

The `PerasCert` data type contains only `pcCertRound` and `pcCertBoostedBlock` — no aggregate signature, no voter list, no VRF proof — so a peer can trivially construct a well-formed cert for any block: [6](#0-5) 

A concrete V1 certificate type with a real BLS aggregate signature exists in `Peras/Cert/V1.hs`, but it is not yet wired into the `BlockSupportsPeras` instance or the inbound validation path. [7](#0-6) 

---

### Impact Explanation

**High — Chain selection manipulation by an unprivileged peer.**

An adversary with a single peer connection can inject one `PerasCert` per Peras round (the DB deduplicates by round number). Each accepted cert adds `perasWeight = 15` to an attacker-chosen block. With `perasRoundLength = 90` slots and `perasWeight = 15`, a minority fork that is 15 blocks shorter than the honest chain can be made to appear heavier. This lets the adversary cause an honest node to switch to a non-canonical chain, violating chain selection safety beyond the intended security assumptions of Ouroboros Peras.

---

### Likelihood Explanation

**High.** The ObjectDiffusion mini-protocol for Peras certificates is reachable from any peer. No stake, no key material, and no prior knowledge beyond the target block's `Point` (slot + hash, both observable from the public chain) are required. The attacker constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = targetPoint }` and sends it; the stub validation accepts it unconditionally.

---

### Recommendation

Replace the stub `validatePerasCert` with the real BLS aggregate-signature verification already implemented in `Peras/Cert/V1.hs` and `Committee/WFALS.hs`. Until the full Cardano-specific `BlockSupportsPeras` instance is wired in, the inbound `processCerts` path should reject all certificates rather than accept them unconditionally. The degenerate instance should either be removed from the production compilation path or replaced with a `validatePerasCert _ _ = Left PerasValidationErr` stub that fails closed. [8](#0-7) 

---

### Proof of Concept

Attacker-controlled entry path (production code, no test scaffolding required):

1. Peer connects to the node's ObjectDiffusion server for Peras certificates.
2. Peer sends a single `MsgObjects` containing:
   ```
   PerasCert { pcCertRound = <any fresh round>, pcCertBoostedBlock = <minority fork tip> }
   ```
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = 15 }`.
4. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
5. `chainSelSync` adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for the minority fork tip.
6. `weightedSelectView` now returns `wsvWeightBoost = 15` for the minority fork.
7. `preferCandidate` returns `ShouldSwitch (Heavier ...)` if the minority fork's total weight exceeds the honest chain's total weight.
8. The node rolls back to the minority fork.

The one-cert-per-round limit (enforced by `Set PerasRoundNo` deduplication in `processCerts`) means the attacker must use a fresh round number for each injection, but with `perasIgnoranceRounds = 487` rounds available before garbage collection, the attacker has ample headroom. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-60)
```haskell
-- | Concrete Peras certificates using BLS signatures
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
```
