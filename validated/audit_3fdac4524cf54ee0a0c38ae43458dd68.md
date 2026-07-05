### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Provided Peras Certificate, Enabling Chain Selection Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. This stub is wired directly into the production certificate ingest path (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can send a crafted `PerasCert` naming any block as the boosted target; the certificate is accepted, stored in `PerasCertDB`, and triggers chain selection. If the boosted block is on a fork fragment already in the `VolatileDB`, the added `PerasWeight` boost can make that fork appear heavier than the honest chain, causing the node to switch away from the canonical chain.

---

### Finding Description

**Root cause — stub validation always succeeds:**

The catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` defines `validatePerasCert` as:

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

No signature is verified, no committee membership is checked, no quorum is confirmed, and no round-number constraints are enforced. The `PerasCert` data type in this instance carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — no cryptographic payload at all. [2](#0-1) 

**Production ingest path calls this stub:**

`makePerasCertPoolWriterFromChainDB` — the production writer for inbound peer certificates — passes `validatePerasCert mkPerasParams` directly to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

`processCerts` accepts the entire batch if all certificates pass `validateCert`, then calls `addCert` (which is `ChainDB.addPerasCertAsync`) for each: [4](#0-3) 

**Chain selection is triggered by the accepted certificate:**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: if the boosted block is in the `VolatileDB` and not already on the current chain, it calls `chainSelectionForBlock` for that block: [5](#0-4) 

**Weight boost is applied to chain comparison:**

`implGetWeightSnapshot` builds the `PerasWeightSnapshot` from all stored certificates. `wsvTotalWeight` adds `wsvBlockNo + wsvWeightBoost` for chain comparison. A fork fragment boosted by a crafted certificate gains `PerasWeight 15` (from `mkPerasParams`), which can tip the comparison in favour of the fork: [6](#0-5) [7](#0-6) 

**`PerasWeight` is `Word64` summed via `Sum Word64` — no overflow guard at the chain-selection comparison level:** [8](#0-7) 

---

### Impact Explanation

An unprivileged peer connected via the Peras object-diffusion mini-protocol can send one or more crafted `PerasCert` messages naming a fork block already present in the node's `VolatileDB`. Because `validatePerasCert` always returns `Right`, the certificate is stored and chain selection is re-run with the fork fragment now carrying an extra `PerasWeight 15` boost. If the fork's `blockNo + boost` exceeds the current chain's total weight, the node switches to the adversarial fork — accepting a non-canonical chain without any honest quorum having voted for it. This directly violates the Peras security assumption that a weight boost requires a genuine quorum certificate.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

Any peer reachable via the Peras certificate object-diffusion mini-protocol can trigger this. No stake, no keys, and no prior block production are required. The attacker only needs to know a block hash present in the target node's `VolatileDB` (observable via ChainSync headers) and send a single `PerasCert` message naming it. The `chainSelSync` guard that skips certificates for blocks older than the immutable tip is the only runtime filter, but it does not prevent boosting recent fork blocks.

---

### Recommendation

1. **Implement real cryptographic validation in `validatePerasCert`**: verify committee membership, VRF-based sortition proof, aggregate signature over the voted block, and that the round number is within the permitted window. Remove the stub `Right cert` body.
2. **Add a `PerasCert` type field for the cryptographic proof** (aggregate signature / VRF certificate) so the type system enforces that a `ValidatedPerasCert` cannot be constructed without passing through real validation.
3. **Until real validation is in place**, gate the Peras certificate ingest path behind a feature flag so it is not reachable from untrusted peers on any deployed network.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects via the Peras certificate object-diffusion mini-protocol.
2. Peer observes (via ChainSync) a fork block hash `H` at block number `N` in the target node's `VolatileDB` that is not on the current chain.
3. Peer sends `PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = BlockPoint slot H }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
5. `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` finds block `H` in `VolatileDB`, calls `chainSelectionForBlock`.
7. `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork fragment: `N + 15`. If this exceeds the current chain's total weight, the node switches to the fork.

**Relevant code path summary:**

```
peer sends PerasCert
  → processCerts (PerasCert.hs:164)
      → validatePerasCert mkPerasParams cert  -- always Right (SupportsPeras.hs:353)
      → addPerasCertAsync chainDB             -- (ChainSel.hs:309)
          → chainSelSync ChainSelAddPerasCert -- (ChainSel.hs:483)
              → chainSelectionForBlock        -- (ChainSel.hs:531)
                  → preferAnchoredCandidate using PerasWeightSnapshot
                      → wsvTotalWeight = blockNo + PerasWeight 15
                      → ShouldSwitch if fork is heavier
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L84-91)
```haskell
newtype PerasWeight
  = PerasWeight {unPerasWeight :: Word64}
  deriving Show via Quiet PerasWeight
  deriving stock Generic
  deriving newtype (Enum, Eq, Ord, NoThunks, Condense)

deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
```
