### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Allowing Unprivileged Peers to Manipulate Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types contains a `validatePerasCert` implementation that unconditionally returns `Right` (success) without performing any cryptographic or semantic checks. When Peras is enabled, an unprivileged peer can send crafted `PerasCert` objects that pass validation, are stored in the `PerasCertDB`, and inject arbitrary weight boosts into chain selection — allowing the peer to steer an honest node toward a non-canonical chain.

---

### Finding Description

**Root cause — stub validator always succeeds:**

The `BlockSupportsPeras` instance at line 320 is explicitly labeled a "degenerate instance for all blks to get things to compile." Its `validatePerasCert` implementation ignores all certificate content and unconditionally returns `Right`:

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

**Attacker-controlled entry path:**

Inbound Peras certificates arrive via the object diffusion mini-protocol. `makePerasCertPoolWriterFromChainDB` wires the stub validator directly into the inbound processing pipeline:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls this validator for every inbound certificate. Because the stub always returns `Right`, every certificate — regardless of its cryptographic content or claimed boosted block — passes validation and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection impact:**

`chainSelSync` processes each accepted certificate. It adds the cert to `PerasCertDB`, then triggers chain selection for the boosted block: [4](#0-3) 

Chain selection compares candidates using `preferAnchoredCandidate`, which incorporates `PerasWeightSnapshot`. The `WeightedSelectView` compares `wsvTotalWeight` — the sum of block number and weight boost — meaning a fake certificate can make a shorter or otherwise non-preferred chain appear heavier: [5](#0-4) 

The weight boost is accumulated per-point in `PerasWeightSnapshot` and summed over the fragment: [6](#0-5) 

**Exploit flow:**

1. Attacker connects as an unprivileged peer.
2. Attacker sends a `PerasCert` claiming to boost any block on a minority fork.
3. `processCerts` calls `validatePerasCert` → always `Right`.
4. Cert is stored in `PerasCertDB` and triggers chain selection.
5. The minority fork's `wsvTotalWeight` is inflated by `perasWeight params`.
6. `preferCandidate` returns `ShouldSwitch` for the boosted fork.
7. The honest node switches to the attacker-controlled chain.

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

When Peras is enabled, any connected peer can inject fake weight boosts into chain selection without possessing any committee keys, stake, or VRF credentials. This directly undermines the Ouroboros chain selection invariant that the preferred chain must be the densest/heaviest honest chain. The attacker gains the same control over chain selection that M-18 granted over tier expansion — but with a more direct consensus safety consequence, since chain selection determines which blocks become immutable.

---

### Likelihood Explanation

Peras is disabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference`), so this is not exploitable on mainnet today. However, the stub is wired into the production inbound processing pipeline unconditionally. Any deployment that enables Peras — including testnets, benchmarks, or future mainnet activation — is immediately vulnerable without any additional attacker capability beyond peer connectivity.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the declared voter set.
2. Each voter's committee eligibility (VRF output and seat index).
3. The boosted block's existence and slot validity.
4. The round number is within the acceptable window.

Until real validation is implemented, the Peras certificate inbound path should be gated behind the Peras feature flag so that the stub is never reachable when Peras is disabled. [7](#0-6) 

---

### Proof of Concept

```
Precondition: Peras enabled on a test network.

1. Attacker peer connects to honest node N.
2. Attacker sends PerasCert { pcCertRound = R, pcCertBoostedBlock = B }
   where B is the tip of an adversarial fork F that is 1 block shorter
   than the honest chain H.
3. processCerts calls validatePerasCert → Right (no checks performed).
4. cert is stored; chainSelSync triggers chainSelectionForBlock for B.
5. weightBoostOfFragment(F) = perasWeight params > 0.
6. wsvTotalWeight(F) = blockNo(F) + perasWeight > wsvTotalWeight(H).
7. preferCandidate returns ShouldSwitch → node adopts F.
8. Attacker has caused N to select a non-canonical chain without any
   committee credentials.
``` [3](#0-2) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
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
