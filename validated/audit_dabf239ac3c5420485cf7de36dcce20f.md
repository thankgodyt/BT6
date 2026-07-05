### Title
Peras Certificate Validation Bypass Allows Any Peer to Manipulate Chain Selection Weight — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can therefore send a crafted `PerasCert` naming any block in the target node's VolatileDB, have it accepted as "validated," and cause that block's chain to receive the full Peras weight boost in chain selection — potentially making the node switch to a fork it would otherwise reject.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub shipped as production code.**

The `BlockSupportsPeras` class defines a `validatePerasCert` method that is supposed to authenticate a Peras certificate before it influences chain selection. The only concrete instance in the codebase is the degenerate catch-all instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This stub is not confined to tests. The production pool writer `makePerasCertPoolWriterFromChainDB` passes it directly as the validator for every inbound certificate received from a peer:

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

**End-to-end exploit path:**

1. **Peer sends a crafted `PerasCert`** via the Peras ObjectDiffusion miniprotocol. The cert contains a peer-chosen `pcCertBoostedBlock` pointing to any block hash the attacker knows is in the target node's VolatileDB (block hashes are public).

2. **`processCerts` calls `validatePerasCert mkPerasParams cert`**, which unconditionally returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }`. No signature, no committee membership, no round validity, no quorum check is performed. [3](#0-2) 

3. **The "validated" cert is enqueued** via `ChainDB.addPerasCertAsync`, which writes it to the `PerasCertDB` and queues a `ChainSelAddPerasCert` message. [4](#0-3) 

4. **`chainSelSync` processes the cert.** The only guards are: (a) is the boosted block older than the immutable tip? (b) is it already in the DB? (c) is it on the current chain? (d) is the boosted block in the VolatileDB? If the attacker targets a block in the VolatileDB that is *not* on the current chain, all guards pass and `chainSelectionForBlock` is triggered for the boosted block. [5](#0-4) 

5. **Chain selection now uses the inflated `PerasWeightSnapshot`.** `weightedSelectView` computes `wsvTotalWeight = blockNo + weightBoostOfFragment`, and `preferCandidate` switches to the candidate if its total weight exceeds the current chain's total weight. [6](#0-5) 

The boost magnitude is `perasWeight params` (from `mkPerasParams`), which is the full configured Peras boost. A fork that is shorter by up to `perasWeight params` blocks can be made to appear heavier than the honest chain.

---

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

When Peras is enabled, any peer can cause an honest node to prefer a non-canonical fork by injecting a fabricated certificate that boosts a block on that fork. The node will switch to the fork if its total Peras weight (block count + injected boost) exceeds the current chain's weight. This violates the chain selection invariant that only legitimately certified blocks should receive a boost, and can cause divergence from the honest chain without the attacker holding any stake or keys.

---

### Likelihood Explanation

**High when Peras is enabled.** The attack requires only:
- Network connectivity to the target node (any peer in the ObjectDiffusion overlay).
- Knowledge of a block hash in the target's VolatileDB (all block hashes are public).
- Sending a single well-formed CBOR-encoded `PerasCert` message.

No stake, no keys, no cryptographic capability is required. The CHANGELOG confirms the Peras cert path is wired into the production `ChainDB` and chain selection. [7](#0-6) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate carries a valid aggregate signature from a quorum of committee members for the stated round.
2. The `pcCertRound` is within the valid window (not from a past or future round outside the protocol's tolerance).
3. The `pcCertBoostedBlock` refers to a block that was actually a candidate in that round.

Until real validation is implemented, the `validatePerasCert` stub must not be used in the production `makePerasCertPoolWriterFromChainDB` path. A temporary mitigation is to reject all inbound certificates at the miniprotocol layer when Peras is in the stub-validation state.

---

### Proof of Concept

**Private testnet sequence:**

1. Start a node with Peras enabled.
2. Let it sync to a chain tip `T` with the honest chain at block number `N`.
3. Identify a block `B` on a competing fork at block number `N - D` (where `D < perasWeight params`) that is present in the node's VolatileDB.
4. Connect as a peer and send a `PerasCert` message:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = Point(slot(B), hash(B)) }
   ```
5. `validatePerasCert` returns `Right` unconditionally.
6. The cert is stored; `chainSelectionForBlock` is triggered for `B`.
7. The fork containing `B` now has total weight `(N - D) + perasWeight params > N` (the honest chain's weight).
8. The node switches to the shorter, non-canonical fork. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
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

**File:** CHANGELOG.md (L92-97)
```markdown
- Add modules `Ouroboros.Consensus.Storage.PerasCertDB{,.API,.Impl}`, notably defining the types`PerasCertDB`, `PerasCertSnapshot` (read-only snapshot of certs contained in the DB), and `AddPerasCertResult`; alongside their respective methods
- Add modules `Test.Ouroboros.Storage.PerasCertDB{,.StateMachine,.Model}` for q-s-m testing of the `PerasCertDB` datatype. The corresponding tests are included in the test suite defined by `Test.Ouroboros.Storage`

- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```
