### Title
Empty `PerasCertDB` on Node Restart Causes Sub-Optimal Initial Chain Selection Under Peras - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

The `PerasCertDB` is a purely in-memory structure with no persistence across node restarts. On every startup, `initialChainSelection` is fed an empty `PerasWeightSnapshot`, meaning all Peras weight boosts are treated as zero. When Peras is enabled, this mirrors the H-4 pattern exactly: a restoration operation (initial chain selection after restart) assumes a "balanced" state (no boosts) when the actual network state may be "imbalanced" (boosted blocks exist), causing the node to prefer a non-canonical chain that is longer by block number but lighter by total Peras weight.

---

### Finding Description

`PerasCertDB.createDB` unconditionally initialises the database from `initialPerasCertDbState`, which contains empty maps for all certificate fields: [1](#0-0) 

`createDB` always starts from this empty state — there is no snapshot, no replay, and no recovery path: [2](#0-1) 

During `ChainDB` initialisation, the freshly-created (empty) `PerasCertDB` is queried for its weight snapshot, and that empty snapshot is passed directly into `initialChainSelection`: [3](#0-2) 

`getWeightSnapshot` over an empty DB returns `mkPerasWeightSnapshot []`, i.e. zero boost for every block: [4](#0-3) 

Chain selection compares candidates by `wsvTotalWeight = wsvBlockNo + wsvWeightBoost`. With an empty snapshot, `wsvWeightBoost` is always `PerasWeight 0`, so the comparison degenerates to pure block-number comparison — identical to Praos without Peras: [5](#0-4) 

The test model explicitly acknowledges this gap with a TODO: [6](#0-5) 

The `SecurityParam` is also reinterpreted as a weight bound under Peras, so the immutable-tip boundary (`takeVolatileSuffix`) is also computed incorrectly when the snapshot is empty: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

When Peras is enabled, the honest chain may contain a block `B` that has been certified and carries a weight boost (e.g. `PerasWeight 15`). An adversary can maintain a competing fork that is one block longer by block number but carries no Peras boost. After a node restart:

- **Honest chain**: `wsvTotalWeight = BlockNo 100 + PerasWeight 15 = 115` (correct, with certs)
- **Adversary chain**: `wsvTotalWeight = BlockNo 101 + PerasWeight 0 = 101`

Without the certificates, the node computes:

- **Honest chain**: `wsvTotalWeight = BlockNo 100 + 0 = 100`
- **Adversary chain**: `wsvTotalWeight = BlockNo 101 + 0 = 101`

`preferCandidate` returns `ShouldSwitch` for the adversary's chain. The node adopts the non-canonical fork. If the node is a block producer, it extends the adversary's chain, and the immutable-tip boundary is also shifted incorrectly (because `takeVolatileSuffix` uses the empty snapshot), potentially causing blocks that should still be volatile to be treated as immutable — or vice versa.

This matches the allowed impact: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

Peras is currently disabled by default (the `eraPerasRoundLength` field defaults to `Nothing`). However:

1. The feature flag is present in production code and is designed to be enabled.
2. A node restart is a routine operational event (software upgrade, crash recovery, hardware maintenance) — it does not require any operator compromise.
3. The adversary only needs to be a connected peer at the moment of restart and to have a fork that is one block longer by block number. No stake, no keys, and no special privileges are required.
4. The window of vulnerability lasts until the node re-receives the relevant Peras certificates from peers, which may take multiple round-trip times.

---

### Recommendation

Persist Peras certificates to disk (analogous to how the `ImmutableDB` and `VolatileDB` are persisted) and replay them during `ChainDB` initialisation before `initialChainSelection` is called. The existing TODO at `https://github.com/tweag/cardano-peras/issues/122` tracks this gap. Until persistence is implemented, `initialChainSelection` should at minimum wait for a quorum of peers to re-deliver their certificate sets before committing to an initial chain, or the node should document that Peras chain-selection guarantees do not hold across restarts.

---

### Proof of Concept

```
T0: Peras enabled. Honest chain tip = Block #100 (slot 100), boosted by cert C
    with PerasWeight 15. Adversary fork tip = Block #101 (slot 101), no cert.
    Honest total weight = 115; adversary total weight = 101.
    Running node correctly selects honest chain.

T1: Node restarts. PerasCertDB initialised empty (initialPerasCertDbState).
    initialChainSelection called with emptyPerasWeightSnapshot.

T2: Adversary peer connects first and offers its fork (block #101).
    Node computes:
      honest  wsvTotalWeight = 100 + 0 = 100   (cert C not yet known)
      adversary wsvTotalWeight = 101 + 0 = 101
    preferCandidate returns ShouldSwitch → node adopts adversary fork.

T3: Node begins extending adversary fork. If node is a block producer it
    mints Block #102 on top of the adversary chain.

T4: Honest peers eventually deliver cert C. Node now sees:
      honest  wsvTotalWeight = 100 + 15 = 115
      adversary wsvTotalWeight = 102 + 0 = 102
    Node switches back, but has already extended the wrong fork and
    potentially made that fork visible to downstream peers.
```

The root cause — `initialPerasCertDbState` always being empty and `initialChainSelection` consuming it without any recovery — is directly analogous to `restoreVault` performing a proportional deposit without checking whether the pool is still balanced.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L67-76)
```haskell
initialPerasCertDbState :: WithFingerprint (PerasCertDbState blk)
initialPerasCertDbState =
  WithFingerprint
    PerasCertDbState
      { pcdsCertIds = Set.empty
      , pcdsCertsByTicket = Map.empty
      , pcdsLastTicketNo = zeroPerasCertTicketNo
      , pcdsLatestCertSeen = Nothing
      }
    (Fingerprint 0)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L132-161)
```haskell
createDB ::
  forall m blk.
  ( IOLike m
  , StandardHash blk
  ) =>
  Complete PerasCertDbArgs m blk ->
  m (PerasCertDB m blk)
createDB args = do
  pcdbState <-
    newTVarWithInvariantIO
      (either Just (const Nothing) . invariantForPerasCertDbState)
      initialPerasCertDbState
  let env =
        PerasCertDbEnv
          { pcdbTracer
          , pcdbState
          }
  pure
    PerasCertDB
      { addCert = implAddCert env
      , getCertIds = implGetCertIds env
      , getCertsAfter = implGetCertsAfter env
      , getWeightSnapshot = implGetWeightSnapshot env
      , getLatestCertSeen = implGetLatestCertSeen env
      , garbageCollect = implGarbageCollect env
      }
 where
  PerasCertDbArgs
    { pcdbaTracer = pcdbTracer
    } = args
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs (L199-218)
```haskell
    perasCertDB <- PerasCertDB.createDB argsPerasCertDB
    perasVoteDB <- PerasVoteDB.createDB argsPerasVoteDB

    varInvalid <- newTVarIO (WithFingerprint Map.empty (Fingerprint 0))

    let initChainSelTracer = TraceInitChainSelEvent >$< tracer

    traceWith initChainSelTracer StartedInitChainSelection
    initialLoE <- Args.cdbsLoE cdbSpecificArgs
    initialWeights <- atomically $ PerasCertDB.getWeightSnapshot perasCertDB
    chain <-
      ChainSel.initialChainSelection
        immutableDB
        volatileDB
        lgrDB
        initChainSelTracer
        (Args.cdbsTopLevelConfig cdbSpecificArgs)
        varInvalid
        (void initialLoE)
        (forgetFingerprint initialWeights)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L1174-1189)
```haskell
-- TODO: update to account for persisted Peras certificates.
-- see https://github.com/tweag/cardano-peras/issues/122
wipeVolatileDB ::
  forall blk.
  (LedgerSupportsProtocol blk, LedgerTablesAreTrivial ExtLedgerState blk) =>
  TopLevelConfig blk ->
  Model blk ->
  (Point blk, Model blk)
wipeVolatileDB cfg m =
  (tipPoint m', reopen m')
 where
  m' =
    (closeDB m)
      { volatileDbBlocks = Map.empty
      , perasCertModel = PerasCertDBModel.openDB PerasCertDBModel.initModel
      , perasVoteModel = PerasVoteDBModel.openDB (PerasVoteDBModel.initModel mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
```
