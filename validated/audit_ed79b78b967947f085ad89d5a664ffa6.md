### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unprivileged Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production implementation of `validatePerasCert` — the degenerate `BlockSupportsPeras` instance — always returns `Right` without performing any cryptographic or structural check. Because the inbound certificate processing path in `PerasCert.hs` passes this stub directly as the validator, any unprivileged peer can send arbitrarily crafted `PerasCert` objects that are unconditionally accepted, stored in the `PerasCertDB`, and used to inflate the Peras weight of an attacker-chosen block, potentially causing the node to switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate for accepting inbound Peras certificates. The only current instance is the degenerate catch-all:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
```

Every certificate, regardless of content, is accepted and assigned the full `perasWeight` boost. [1](#0-0) 

**Inbound network path — `processCerts`:**

`makePerasCertPoolWriterFromChainDB` wires this stub directly into the object-diffusion mini-protocol writer that processes certificates arriving from peers:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
```

`processCerts` calls `partitionEithers (validateCert <$> certsNotAlreadyInDb)`. Because `validateCert` always returns `Right`, the left partition is always empty and every certificate is forwarded to `addCert` (i.e., `ChainDB.addPerasCertAsync`). [2](#0-1) [3](#0-2) 

**Weight accumulation — `PerasWeightSnapshot`:**

Accepted certificates are stored in `PerasCertDB` keyed by round number. `implGetWeightSnapshot` builds the `PerasWeightSnapshot` by summing `getPerasCertBoost` for every stored certificate. Duplicate boosted-block points have their weights combined (`mkPerasWeightSnapshot` merges duplicates). [4](#0-3) 

**Chain selection — `weightBoostOfFragment`:**

`weightBoostOfFragment` sums the boost of every point on a candidate fragment. `WeightedSelectView.preferCandidate` switches to a candidate when its `wsvTotalWeight` (block number + weight boost) exceeds the current chain's. [5](#0-4) [6](#0-5) 

**Analog mapping to the external report:**

| External report | This codebase |
|---|---|
| `setSwapInFeeRate()` setter with no timelock | `validatePerasCert` with no actual check |
| Owner sets fee to 100 % before user's swap | Peer sends N certificates (one per round) boosting attacker block |
| User's collateral captured via inflated fee | Node's chain selection captured via inflated weight |
| `debtOutMin = 0` leaves user unprotected | No validation leaves node unprotected |

---

### Impact Explanation

When Peras is enabled via `rnFeatureFlags`, an attacker who connects as a peer can:

1. Send `PerasCert` objects for rounds `r₁, r₂, …, rₙ` (each a distinct round number, so none are filtered by the `alreadyInDb` check), all with `pcCertBoostedBlock` pointing to a block on the attacker's preferred fork.
2. Each certificate is accepted unconditionally and stored; the boosted block accumulates a total weight of `n × 15`.
3. `addPerasCertAsync` triggers `chainSelectionForBlock` for the boosted block. If the honest chain's block-number lead is less than `n × 15`, `preferCandidate` returns `ShouldSwitch` and the node adopts the attacker's fork.

This constitutes a **chain-selection safety failure**: an unprivileged peer causes an honest node to prefer a non-canonical chain, matching the "High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" impact tier. [7](#0-6) 

---

### Likelihood Explanation

- **Peras must be enabled** via the `rnFeatureFlags` feature flag; it is disabled by default. Once enabled on any testnet or future mainnet deployment, the attack surface is immediately open to any connected peer.
- **No cryptographic material is required.** The attacker needs only a valid TCP connection and knowledge of a target block's `Point`.
- **The attack is cheap and repeatable.** Sending N certificates costs O(N) network messages; there is no proof-of-work or stake requirement.
- **The only partial mitigation** is the `olderThanImmTip` check in `chainSelSync`, which ignores certificates for blocks already past the immutable tip — but this does not prevent boosting recent volatile blocks.

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify the certificate's BLS/committee signature, confirm the round number falls within the valid window, and check that the boosted block is known and on a plausible chain.
2. **Do not ship the stub to any Peras-enabled deployment** until issue [#120](https://github.com/tweag/cardano-peras/issues/120) is resolved.
3. **Add a per-round weight cap** in `PerasWeightSnapshot` so that even a fully valid certificate cannot boost a block beyond the protocol-specified maximum.
4. **Rate-limit inbound certificates per peer** in `processCerts` to bound the worst-case weight inflation an attacker can inject before being disconnected.

---

### Proof of Concept

```
1. Run a Cardano node with Peras enabled (rnFeatureFlags).
2. Connect as an unprivileged peer via the object-diffusion mini-protocol.
3. Obtain the Point of block B on a minority fork F (e.g., from the VolatileDB).
4. Craft PerasCert { pcCertRound = r, pcCertBoostedBlock = B } for r = 1..N.
5. Send all N certificates in one batch via opwAddObjects.
6. processCerts calls validatePerasCert mkPerasParams for each cert → all return Right.
7. Each cert is stored in PerasCertDB; implGetWeightSnapshot returns boost N×15 for B.
8. addPerasCertAsync triggers chainSelectionForBlock for B.
9. weightedSelectView computes wsvTotalWeight(F) = blockNo(F) + N×15.
10. If blockNo(honest) - blockNo(F) < N×15, preferCandidate returns ShouldSwitch.
11. Node adopts fork F.
``` [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-268)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)

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
