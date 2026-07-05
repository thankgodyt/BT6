### Title
Unconditional `validatePerasCert` Acceptance Enables Peer-Injected Chain Selection Manipulation via Peras Weight Boost — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` return, performing zero cryptographic or semantic validation on Peras certificates received from peers. An unprivileged peer can send a crafted certificate boosting any block hash in the victim's VolatileDB; the certificate is accepted without verification, stored in the `PerasCertDB`, and used to influence chain selection via the Peras weight mechanism — potentially causing the node to prefer a fork it would otherwise reject.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub used in production**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates. The only instance in the entire codebase is a degenerate "TODO" instance that unconditionally returns `Right` for every certificate, assigning it the full configured Peras weight boost:

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

This is not a test stub — it is the only `BlockSupportsPeras` instance, declared as a catch-all `instance StandardHash blk => BlockSupportsPeras blk`, meaning it applies to every block type including `CardanoBlock`. [2](#0-1) 

**Production inbound path calls this stub directly**

`makePerasCertPoolWriterFromChainDB` — the production writer used in the node-to-node cert diffusion handler — passes `validatePerasCert mkPerasParams` as the validation function for every peer-supplied cert batch:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` then calls this validator on every cert not already in the DB. Since it always returns `Right`, every cert passes and is forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**The cert diffusion protocol is wired into the production node-to-node stack**

The `hPerasCertDiffusionClient` handler is unconditionally set up in the production `Handlers` record, calling `makePerasCertPoolWriterFromChainDB`: [5](#0-4) 

**Accepted certs trigger chain selection with attacker-controlled weight**

`chainSelSync` processes each accepted cert: it looks up the cert's `pcCertBoostedBlock` in the VolatileDB, and if found, calls `chainSelectionForBlock` for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

`preferAnchoredCandidate` switches from standard chain selection to weighted chain selection the moment the `PerasWeightSnapshot` is non-empty:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      -- standard Praos chain selection
  | otherwise =
      -- weighted Peras chain selection using weightedSelectView
``` [7](#0-6) 

The `WeightedSelectView` compares chains by `wsvTotalWeight = blockNo + weightBoost`, so an injected boost of `perasWeight params` can make a shorter fork outweigh the honest chain: [8](#0-7) 

---

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An attacker with a network connection can inject a crafted `PerasCert` that:
1. Passes `validatePerasCert` unconditionally (no signature, no committee membership, no quorum check).
2. Is stored in the `PerasCertDB` and reflected in the `PerasWeightSnapshot`.
3. Causes `preferAnchoredCandidate` to switch to weighted comparison, where the attacker-boosted fork gains `perasWeight params` extra weight.
4. Triggers `chainSelectionForBlock` for the boosted block, potentially causing the node to switch to a fork it would otherwise reject.

This matches the allowed High impact: *"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The attack requires only:
- A network connection to the victim node (the `PerasCertDiffusion` miniprotocol is wired into the production NtN stack).
- A block hash present in the victim's VolatileDB, obtainable via ChainSync.
- Crafting a `PerasCert` CBOR value with an arbitrary `pcCertRound` and `pcCertBoostedBlock` — a trivial serialization task given the public `Serialise` instance.

No keys, stake, or privileged access are required. The `validatePerasCert` stub is explicitly marked TODO and is the only implementation, so there is no secondary validation gate.

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify committee membership for the claimed round, check a quorum of valid committee-member signatures over `(round, boostedBlock)`, and confirm the round number is within the valid window relative to the current ledger state.
2. **Gate cert processing on Peras being enabled**: `chainSelSync` should check whether the current era has Peras enabled (non-null `eraPerasRoundLength`) before adding a cert to the `PerasCertDB` or triggering chain selection.
3. **Do not use the degenerate instance in production**: the `instance StandardHash blk => BlockSupportsPeras blk` catch-all should be replaced with era-specific instances that implement real validation, or the catch-all should unconditionally return `Left PerasValidationErr` until proper validation is in place.

---

### Proof of Concept

```
1. Attacker connects to victim node via the PerasCertDiffusion miniprotocol.

2. Attacker learns block hash H at slot S from the victim's VolatileDB
   (e.g., via ChainSync — the tip or any recent block).

3. Attacker crafts:
     PerasCert { pcCertRound = R        -- any round not yet in victim's PerasCertDB
               , pcCertBoostedBlock = BlockPoint S H }

4. Attacker sends the cert via the diffusion protocol.

5. processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = W })

6. addPerasCertAsync enqueues the cert for chainSelSync.

7. chainSelSync:
   - Looks up H in VolatileDB → found (boostedHdr)
   - Calls chainSelectionForBlock for boostedHdr

8. constructPreferableCandidates reads the now-non-empty PerasWeightSnapshot.
   preferAnchoredCandidate takes the `otherwise` branch (weighted comparison).
   Any chain containing H now has weight += W.

9. If the attacker-boosted fork's total weight exceeds the current chain's total
   weight, the node switches to the fork.
``` [1](#0-0) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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
