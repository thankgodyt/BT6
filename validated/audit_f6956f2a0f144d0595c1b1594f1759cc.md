### Title
`validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain Weight Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or semantic checks. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted block. The certificate passes "validation," is stored in the `PerasCertDB`, and triggers chain selection that adds `perasWeight = 15` to the attacker-chosen block's weight, potentially causing the node to prefer a non-canonical fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub in production code:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No signature is verified. No quorum is checked. No committee membership is confirmed. The entire `cert` argument — including its peer-controlled `pcCertBoostedBlock :: Point blk` — is accepted verbatim.

**This stub is wired into the production inbound-certificate path:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` — explicitly documented as the production writer — passes `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`. `processCerts` calls this function on every inbound certificate and, if it returns `Right`, stores the certificate and calls `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Chain selection then acts on the accepted certificate:**

`chainSelSync` in `ChainSel.hs` processes the stored certificate. It reads `getPerasCertBoostedBlock cert` — the attacker-supplied block point — and, if that block is present in the `VolatileDB`, calls `chainSelectionForBlock` for it. [4](#0-3) 

The boosted block's weight is then reflected in the `PerasWeightSnapshot`, which is used by `WeightedSelectView` to compute `wsvTotalWeight = blockNo + weightBoost`. A fragment containing the boosted block gains `PerasWeight 15` (the default `perasWeight`). [5](#0-4) 

**The `PerasCert` data type carries only peer-supplied fields:** [6](#0-5) 

`pcCertRound` and `pcCertBoostedBlock` are both fully attacker-controlled. There is no signature field in this stub type, so there is nothing to verify even if the code tried.

**Analog to the external report:**

| DODO vulnerability | Ouroboros analog |
|---|---|
| `params.fromToken` not validated against deposited `zrc20` | `cert` fields not validated against any committee/quorum/signature |
| Contract approves its own balance of attacker-specified token | Node adds attacker-specified `pcCertBoostedBlock` to weight snapshot |
| Missing check: `params.fromToken == zrc20` | Missing check: cert aggregate signature, quorum, committee membership |
| Impact: fund drain | Impact: chain selection manipulation |

---

### Impact Explanation

An unprivileged peer can cause an honest node to prefer a non-canonical fork. By sending a `PerasCert` with `pcCertBoostedBlock` pointing to a block on an adversarial fork, the attacker injects `PerasWeight 15` into that fork's total weight. Since `wsvTotalWeight = blockNo + weightBoost`, a fork up to 15 blocks shorter than the honest chain becomes preferred. This is a **High** chain-selection bug: it lets an unprivileged peer make an honest node adopt a less-secure chain beyond the intended security assumptions of Praos/Peras, violating the Common Prefix property.

---

### Likelihood Explanation

The attack requires only a connected peer and the ability to send a crafted `PerasCert` message over the Peras certificate mini-protocol. No keys, stake, or privileged access are needed. The `processCerts` function is reachable from any peer that can submit objects via the object-diffusion protocol. The only precondition is that the target block must already be in the node's `VolatileDB` (i.e., the attacker's fork block has been received), which is a normal condition during chain sync.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregated public keys of the claimed voters.
2. Checks that the set of voters constitutes a valid quorum (total stake ≥ `perasQuorumStakeThreshold`).
3. Verifies each voter's committee membership and eligibility proof (persistent vs. non-persistent seat).

Until the real implementation is in place, the production pool writers (`makePerasCertPoolWriterFromChainDB`, `makePerasCertPoolWriterFromCertDB`) should not be wired into a live node, or should reject all inbound certificates with a hard `Left`.

---

### Proof of Concept

1. Node A is honest, running with Peras enabled. Its `VolatileDB` contains block `B_adv` on an adversarial fork that is 10 blocks shorter than the honest chain tip.
2. Attacker (peer) constructs `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = pointOf(B_adv) }`.
3. Attacker sends this certificate via the Peras cert mini-protocol to Node A.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
5. Certificate is stored; `addPerasCertAsync` is called.
6. `chainSelSync` finds `B_adv` in `VolatileDB`, calls `chainSelectionForBlock` for it.
7. `constructPreferableCandidates` computes `wsvTotalWeight` for the adversarial fork: `blockNo(B_adv) + 15`. If this exceeds the honest chain's `blockNo`, Node A switches to the adversarial fork.
8. Node A now tracks a non-canonical chain, violating Common Prefix. [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-544)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
 where
  tracer :: Tracer m (TraceAddPerasCertEvent blk)
  tracer = TraceAddPerasCertEvent >$< cdbTracer

  certRound :: PerasRoundNo
  certRound = getPerasCertRound cert

  boostedBlock :: Point blk
  boostedBlock = getPerasCertBoostedBlock cert
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
