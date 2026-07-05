### Title
Unconditional Peras Certificate Acceptance Bypasses Quorum Validation, Enabling Chain Selection Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The production Peras certificate inbound processing path calls `validatePerasCert mkPerasParams`, which is a stub that unconditionally accepts every certificate without performing any quorum, signature, or committee membership check. An unprivileged peer can send a crafted `PerasCert` message that boosts an arbitrary block by `PerasWeight 15`, causing an honest node to prefer a non-canonical fork via the weighted chain selection rule.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate before it is stored and used to influence chain selection. The degenerate instance (the only instance currently in the codebase) implements this gate as an unconditional pass-through:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
``` [1](#0-0) 

No check is performed on:
- Whether the certificate is backed by a quorum of stake-weighted votes (`stakeAboveThreshold`)
- Whether the certificate's cryptographic signatures are valid
- Whether the voter IDs belong to the elected committee
- Whether the round number is valid relative to the current chain state

This stub is wired directly into both production pool writers that handle inbound certificates from peers:

```haskell
makePerasCertPoolWriterFromCertDB:
  (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

makePerasCertPoolWriterFromChainDB:
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
``` [2](#0-1) 

The `processCerts` function, which is the actual inbound handler for peer-supplied certificates, calls this validator and adds every certificate that passes it to the `PerasCertDB`: [3](#0-2) 

Once stored, the certificate's boost is incorporated into the `PerasWeightSnapshot`, which is read by `weightedSelectView` and used in `preferCandidate` to compare chain fragments:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
    ...
``` [4](#0-3) 

The total weight is `blockNo + weightBoost`, so a fabricated certificate adding `PerasWeight 15` can override the natural chain selection for any two forks that differ by fewer than 15 blocks. [5](#0-4) 

The contrast with the vote aggregation path is instructive: when votes are aggregated locally, `votesReachQuorum` enforces `stakeAboveThreshold` (requiring ≥ 77% of committee stake) before a certificate is forged. This check is entirely absent for certificates received from peers. [6](#0-5) 

---

### Impact Explanation

This is a **High** impact chain selection bug. An unprivileged peer can make an honest node prefer a non-canonical or adversarially-chosen fork by injecting a fabricated certificate. The `PerasWeight 15` boost is the configured mainnet value and is sufficient to override the natural longest-chain rule for forks within a 15-block window. Because `addPerasCertAsync` triggers a full chain selection run after each accepted certificate, the effect is immediate and persistent until the boosted block becomes immutable or is rolled back. [7](#0-6) 

---

### Likelihood Explanation

Any connected peer can send a `PerasCert` message via the Peras certificate object-diffusion mini-protocol. The attacker needs only to know the hash of a block they wish to boost (publicly available from the chain). No stake, keys, or committee membership is required. The attack is cheap and repeatable every round.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies that the certificate is backed by a set of votes whose total `PerasVoteStake` satisfies `stakeAboveThreshold` (i.e., ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
2. Verifies each vote's cryptographic signature against the voter's registered key.
3. Verifies that each voter belongs to the elected committee for the certificate's round.
4. Verifies the round number is within the valid acceptance window.

Until the real implementation is in place, the production pool writers (`makePerasCertPoolWriterFromCertDB`, `makePerasCertPoolWriterFromChainDB`) should reject all inbound certificates rather than accept them unconditionally. [8](#0-7) 

---

### Proof of Concept

1. Attacker connects to an honest node as a peer via the node-to-node protocol.
2. Attacker observes that fork `F` (a chain they control or prefer) is currently losing chain selection against the canonical chain `C` by fewer than 15 blocks of weight.
3. Attacker constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = tipOf(F) }` with an arbitrary round number `r` and the tip of `F` as the boosted block. No votes, signatures, or committee membership are needed.
4. Attacker sends this certificate to the honest node via the Peras certificate diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })` unconditionally.
6. The certificate is stored in `PerasCertDB`; `implGetWeightSnapshot` now includes `(tipOf(F), PerasWeight 15)` in the weight snapshot.
7. `addPerasCertAsync` enqueues a chain selection run for the boosted block.
8. `chainSelectionForBlock` computes `weightedSelectView` for `F`, which now has `wsvTotalWeight = blockNo(F) + 15`, exceeding `wsvTotalWeight` of `C`.
9. `preferCandidate` returns `ShouldSwitch`; the honest node switches to fork `F`. [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
