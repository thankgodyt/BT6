### Title
`PerasCertDB` Always Initialized Empty on Node Restart Causes Chain Selection to Ignore Accumulated Peras Boosts — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

The `PerasCertDB` is always created with `initialPerasCertDbState` (all fields zeroed/empty) and is never persisted to disk. After any node restart, the `PerasWeightSnapshot` derived from it is `emptyPerasWeightSnapshot`. Chain selection then falls back to pure block-count comparison, ignoring all Peras boosts that had been accumulated for volatile blocks before the restart. An adversary who presents a longer-by-block-count but less-boosted chain during this window can cause the restarted node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — always-empty initialization:**

`createDB` unconditionally initialises the database from `initialPerasCertDbState`:

```haskell
initialPerasCertDbState =
  WithFingerprint
    PerasCertDbState
      { pcdsCertIds        = Set.empty
      , pcdsCertsByTicket  = Map.empty
      , pcdsLastTicketNo   = zeroPerasCertTicketNo
      , pcdsLatestCertSeen = Nothing
      }
    (Fingerprint 0)
``` [1](#0-0) 

`createDB` always passes this value to `newTVarWithInvariantIO`; there is no code path that reads previously accumulated certificates from the VolatileDB or ImmutableDB: [2](#0-1) 

**Weight snapshot derived from the empty map:**

`implGetWeightSnapshot` builds the `PerasWeightSnapshot` exclusively from `pcdsCertsByTicket`, which is empty after restart: [3](#0-2) 

**Chain selection uses the empty snapshot:**

`preferAnchoredCandidate` branches on `isEmptyPerasWeightSnapshot weights`. When the snapshot is empty it falls back to pure block-count comparison, discarding all Peras boosts: [4](#0-3) 

`getCurrentChainLike` also calls `takeVolatileSuffix weights k`, which with an empty snapshot uses only block count to determine the immutable boundary, potentially exposing more blocks as volatile: [5](#0-4) 

**ChainDB opens a fresh `PerasCertDB` on every startup:** [6](#0-5) 

**Acknowledged in the model with a TODO:**

The `wipeVolatileDB` model function resets the cert model to `initModel` and carries an explicit TODO:

```haskell
-- TODO: update to account for persisted Peras certificates.
-- see https://github.com/tweag/cardano-peras/issues/122
perasCertModel = PerasCertDBModel.openDB PerasCertDBModel.initModel
``` [7](#0-6) 

**Secondary effect — `pcdsLatestCertSeen` reset to `Nothing`:**

The `getLatestCertSeen` field is described as a direct precondition for voting in any round after the first. After restart it returns `Nothing`, meaning the node believes it has never seen a certificate, which can affect its own voting eligibility. [8](#0-7) 

---

### Impact Explanation

This is a **High** chain-selection bug. After a restart the node's `PerasWeightSnapshot` is empty, so `preferAnchoredCandidate` compares candidate chains by block count alone. An adversary who has been building a chain with more blocks but fewer Peras boosts can present it to the restarted node during the window before the node re-receives certificates from peers. Because the honest chain's boosts are invisible to the restarted node, the adversary's longer-by-count chain appears heavier, causing the node to switch to a non-canonical chain. This violates the Peras security assumption that boosted blocks are harder to roll back.

---

### Likelihood Explanation

The adversary needs to (a) know or detect that a target node has restarted and (b) have a competing chain with more blocks than the honest chain. Both conditions are realistic: node restarts are observable via peer disconnection/reconnection events, and an adversary who has been withholding blocks can present a longer chain during the restart window. The window closes once the node re-syncs certificates from honest peers, but in a network partition or targeted eclipse scenario the window can be extended.

---

### Recommendation

1. **Persist the `PerasCertDB` to disk** and reload it on startup, analogously to how the LedgerDB snapshot is restored.
2. **Alternatively, repopulate the `PerasCertDB` from the VolatileDB** during `initialChainSelection` by scanning volatile blocks for embedded Peras certificates before performing chain selection.
3. **Enforce the invariant** that `initialChainSelection` is never called with `emptyPerasWeightSnapshot` when the VolatileDB contains blocks from a Peras-enabled era.

---

### Proof of Concept

```
Private testnet sequence:

1. Node A runs normally; rounds 1–100 complete; PerasCertDB accumulates
   100 certificates; honest chain C_honest has total weight
   W_honest = block_count + sum_of_boosts.

2. Adversary B withholds a competing chain C_adv with
   block_count(C_adv) > block_count(C_honest)
   but no Peras certificates (total weight W_adv = block_count(C_adv)).

3. Node A restarts. createDB initialises PerasCertDB with
   initialPerasCertDbState (all empty). getWeightSnapshot returns
   emptyPerasWeightSnapshot.

4. Before Node A re-receives any certificate from honest peers,
   Adversary B connects and presents C_adv.

5. preferAnchoredCandidate sees isEmptyPerasWeightSnapshot = True,
   falls back to block-count comparison:
     block_count(C_adv) > block_count(C_honest)  =>  ShouldSwitch

6. Node A switches to C_adv, accepting a non-canonical chain.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L139-143)
```haskell
createDB args = do
  pcdbState <-
    newTVarWithInvariantIO
      (either Just (const Nothing) . invariantForPerasCertDbState)
      initialPerasCertDbState
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-70)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
```
