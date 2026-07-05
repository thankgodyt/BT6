### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unprivileged Chain Selection Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` degenerate instance's `validatePerasCert` function unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic checks. This stub is wired directly into the production Peras certificate ingestion paths. When Peras is enabled, any unprivileged peer can send crafted certificates that boost an arbitrary block, causing honest nodes to artificially inflate the weight of a non-canonical chain and potentially switch to it — a direct chain-selection safety failure analogous to the SponsorVault subsidy drain in H-03.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The degenerate `BlockSupportsPeras` instance at lines 350–358 of `SupportsPeras.hs` unconditionally accepts every certificate:

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

No BLS aggregate-signature check, no VRF proof verification, no quorum threshold check, no round-number range check — every `PerasCert` from any peer is stamped `ValidatedPerasCert` and assigned the full `perasWeight` boost. [1](#0-0) 

**Production ingestion paths that call this stub:**

Both production `ObjectPoolWriter` factories in `PerasCert.hs` pass `validatePerasCert mkPerasParams` as the validation callback:

```haskell
-- makePerasCertPoolWriterFromCertDB (line 103)
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB (line 126)
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

**`processCerts` accepts the entire batch:**

`processCerts` (lines 164–185) calls `validateCert` on each inbound certificate. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch `([], validatedCerts)` is always taken and every certificate is added to the pool. [3](#0-2) 

**Chain selection is then triggered for the boosted block:**

`chainSelSync` (lines 483–532 of `ChainSel.hs`) receives the accepted certificate, looks up the boosted block in the VolatileDB, and calls `chainSelectionForBlock`. The weight snapshot is updated so that `weightBoostOfFragment` returns the full `perasWeight` for any fragment containing the boosted block. [4](#0-3) 

**`WeightedSelectView.preferCandidate` uses the inflated weight to decide fork switches:**

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
    ...
```

`wsvTotalWeight` sums `wsvBlockNo` and `wsvWeightBoost`; the attacker-injected boost directly shifts this comparison. [5](#0-4) 

**End-to-end exploit path:**

1. Attacker connects to an honest node via the ObjectDiffusion mini-protocol (no stake or keys required).
2. Attacker sends a crafted `PerasCert{pcCertRound = R, pcCertBoostedBlock = <point on attacker's fork>}`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. Certificate is added to `PerasCertDB`; `chainSelSync` is triggered.
5. `chainSelSync` fetches the boosted header from VolatileDB and calls `chainSelectionForBlock`.
6. The attacker's fork fragment gains `perasWeight` additional weight in `weightBoostOfFragment`.
7. If the attacker's fork total weight now exceeds the honest chain's total weight, `preferCandidate` returns `ShouldSwitch` and the node adopts the attacker's fork.

The attacker can repeat this for multiple rounds, stacking boosts, to overcome any honest-chain weight advantage — directly mirroring how the H-03 router owner repeatedly drains the SponsorVault by being both the service provider and the beneficiary of the subsidy.

---

### Impact Explanation

**High — chain selection manipulation / consensus safety failure.**

An unprivileged peer with only network access can cause an honest node to prefer and adopt a non-canonical chain by injecting crafted Peras certificates. This bypasses the entire Peras certificate validation stack (BLS aggregate signature, VRF eligibility proofs, quorum threshold) and constitutes a direct violation of the chain-selection security invariant. The impact is bounded to nodes that have explicitly enabled Peras (disabled by default), but the attack requires no stake, no keys, and no operator compromise.

---

### Likelihood Explanation

**Medium (conditional on Peras being enabled).** The attack requires only the ability to send messages over the ObjectDiffusion mini-protocol — no cryptographic material, no stake, no privileged access. The degenerate instance is the only `BlockSupportsPeras` instance currently compiled into the consensus library (the TODO at line 318 confirms this), so any deployment that enables Peras uses this stub. The barrier is solely the feature flag.

---

### Recommendation

1. **Do not ship the degenerate `validatePerasCert` stub in any Peras-enabled build.** Replace it with a real implementation that verifies the BLS aggregate signature, checks VRF eligibility proofs for non-persistent voters, and enforces the quorum threshold — matching the validation logic already present in `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert`.
2. **Gate the production ingestion paths** (`makePerasCertPoolWriterFromChainDB`, `makePerasCertPoolWriterFromCertDB`) on a non-stub `validatePerasCert` at compile time, so the TODO cannot be silently left in place.
3. **Apply the same scrutiny to `validatePerasVote`** (lines 360–371), which only checks stake-distribution membership and performs no cryptographic signature verification, enabling forged votes from any known voter identity. [6](#0-5) 

---

### Proof of Concept

```
Private testnet with Peras enabled:

1. Start honest node N with Peras enabled.
2. Attacker A produces a valid block B_fork on a competing fork (1 block behind N's tip).
3. A sends PerasCert { pcCertRound = 1, pcCertBoostedBlock = point(B_fork) } to N
   via the ObjectDiffusion inbound handler.
4. processCerts calls validatePerasCert mkPerasParams cert
   → Right (ValidatedPerasCert { vpcCertBoost = perasWeight }) -- no checks
5. chainSelSync receives the cert, fetches B_fork's header from VolatileDB,
   calls chainSelectionForBlock.
6. weightBoostOfFragment now returns perasWeight for any fragment containing B_fork.
7. wsvTotalWeight(fork) = blockNo(B_fork) + perasWeight
   wsvTotalWeight(honest) = blockNo(tip_N) + 0
   If perasWeight > (blockNo(tip_N) - blockNo(B_fork)), preferCandidate returns ShouldSwitch.
8. N switches to A's fork without A having produced a single additional block.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-390)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
