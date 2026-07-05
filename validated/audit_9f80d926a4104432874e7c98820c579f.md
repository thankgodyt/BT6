### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inflate Chain Weight and Hijack Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Any unprivileged peer can therefore send a crafted `PerasCert` that boosts an adversarial chain's Peras weight, causing the victim node to switch away from the honest chain. This is the direct consensus analog of the external report's "donation attack": just as donating yield tokens inflates a price ratio to bypass a borrow limit, sending a fake certificate inflates a chain's `wsvTotalWeight` to bypass the chain-selection preference for the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

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

This is the **only** instance of `BlockSupportsPeras` for all block types (`instance StandardHash blk => BlockSupportsPeras blk`), meaning it covers every concrete block type including Cardano blocks. [2](#0-1) 

**Inbound certificate processing calls this stub directly:**

`processCerts` in the `ObjectPool.PerasCert` module receives certificates from a peer, calls `validatePerasCert mkPerasParams` on each one, and — because the stub always returns `Right` — unconditionally adds every certificate to the `PerasCertDB` and triggers chain selection. [3](#0-2) [4](#0-3) 

**The certificate boost directly inflates chain weight used in chain selection:**

`weightBoostOfFragment` sums the `PerasWeight` of every boosted point on a fragment. `wsvTotalWeight` adds this boost to the block number. `preferCandidate` switches to whichever fragment has the higher `wsvTotalWeight`. [5](#0-4) [6](#0-5) 

**Chain selection acts on the boosted block immediately:**

`chainSelSync` for `ChainSelAddPerasCert` calls `chainSelectionForBlock` on the boosted block, re-evaluating whether the adversarial fork is now heavier than the current selection. [7](#0-6) 

**The diffusion handler is wired unconditionally in the node-to-node stack:**

`makePerasCertPoolWriterFromChainDB` — which embeds the no-op `validatePerasCert` — is installed as the inbound handler for the `PerasCertDiffusion` mini-protocol for every peer connection. [8](#0-7) 

---

### Impact Explanation

When Peras is enabled, any unprivileged peer can:

1. Connect to a victim node via the standard node-to-node `PerasCertDiffusion` mini-protocol.
2. Send a `PerasCert` whose `pcCertBoostedBlock` points to a block on an adversarial fork.
3. Because `validatePerasCert` never rejects anything, the certificate is stored and the adversarial block receives `perasWeight` boost units.
4. `wsvTotalWeight` of the adversarial fragment becomes `BlockNo_adv + perasWeight`, which can exceed `BlockNo_honest` of the honest chain.
5. `preferCandidate` returns `ShouldSwitch`, and the node adopts the adversarial chain.

This is a **High** chain-selection bug: an unprivileged peer makes an honest node prefer a non-canonical, potentially adversary-controlled chain beyond the intended security assumptions of Praos/Peras.

The analogy to the external report is exact:
- **External**: `effectiveSupply` (denominator) is reduced by escrowing; attacker donates yield tokens (numerator) → price ratio inflated → borrow limit bypassed.
- **Consensus**: honest chain's block-number advantage (denominator of the comparison) is overcome; attacker sends a fake certificate (numerator boost) → `wsvTotalWeight` inflated → chain-selection preference bypassed.

---

### Likelihood Explanation

- The `PerasCertDiffusion` mini-protocol is open to any peer that can establish a node-to-node connection — no special privilege is required.
- The attack requires only sending a single well-formed (but cryptographically unverified) `PerasCert` message; no stake, no KES key, no VRF key.
- The vulnerability is active whenever Peras is enabled; the CHANGELOG notes Peras is "disabled by default," but the code path is fully wired and the stub is the only implementation.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that verifies:
- The certificate's aggregate signature over the claimed quorum of votes.
- That the signing committee members are drawn from the correct epoch's stake distribution.
- That the boosted block's slot falls within the correct Peras round window.
- That the certificate round number is not in the future or replayed from a past epoch.

Until real validation is implemented, the `PerasCertDiffusion` inbound handler should reject all certificates (return `Left PerasValidationErr`) rather than accept them unconditionally, so that enabling Peras does not open this attack surface.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  1. Establish NtN connection to victim node
  │  2. Send PerasCertDiffusion message containing:
  │       PerasCert { pcCertRound    = <any round>
  │                 , pcCertBoostedBlock = <point on adversarial fork> }
  │
  ▼
processCerts (ObjectPool/PerasCert.hs:164)
  └─ validatePerasCert mkPerasParams cert
       └─ always returns Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
            (SupportsPeras.hs:353-358)
  └─ addCert → PerasCertDB stores the boost
  └─ ChainDB.addPerasCertAsync → chainSelSync (ChainSel.hs:483)
       └─ chainSelectionForBlock on boosted adversarial block
            └─ weightBoostOfFragment adds perasWeight to adversarial fragment
            └─ wsvTotalWeight(adv) = BlockNo_adv + perasWeight
                                   > BlockNo_honest  (if boost is large enough)
            └─ preferCandidate → ShouldSwitch
            └─ Node adopts adversarial chain  ← consensus safety failure
``` [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
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
