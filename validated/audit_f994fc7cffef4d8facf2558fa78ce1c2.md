### Title
Peras Certificate Validation Unconditionally Accepts Any Certificate, Enabling Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production catch-all `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate, regardless of cryptographic content. Any unprivileged peer connected via the object-diffusion mini-protocol can inject crafted `PerasCert` objects that are accepted without any signature or quorum verification. Accepted certificates are stored in the `PerasCertDB`, update the `PerasWeightSnapshot`, and trigger chain selection — allowing an attacker to artificially boost adversarial fork blocks and cause an honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — unconditional certificate acceptance:**

The catch-all instance in `BlockSupportsPeras.hs` implements `validatePerasCert` as:

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

This is the only instance in scope for all block types until a more specific instance is provided. No cryptographic check, no quorum check, no committee membership check, and no round-number plausibility check is performed.

**Inbound path — object diffusion protocol:**

`makePerasCertPoolWriterFromChainDB` (and `makePerasCertPoolWriterFromCertDB`) wire this stub directly as the validator for all inbound certificates received from peers:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls this validator and, if it returns `Right` (which it always does), timestamps and stores the certificate: [3](#0-2) 

**Chain selection impact — fake weight boost:**

Once stored, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which calls `chainSelSync` → `chainSelectionForBlock`. The `PerasWeightSnapshot` is updated with the fake boost via `addToPerasWeightSnapshot`: [4](#0-3) 

Chain selection then uses `weightedSelectView` to compute `wsvTotalWeight = blockNo + weightBoost` and `preferCandidate` switches to the heavier fragment: [5](#0-4) 

**Exploit flow:**

1. Attacker connects to a node via the object-diffusion mini-protocol (no privileges required).
2. Attacker crafts a `PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlockPoint }` for any round `R` not yet in the `PerasCertDB`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. The cert is stored; `PerasWeightSnapshot` gains `perasWeight = 15` for the adversarial block.
5. `chainSelectionForBlock` is triggered for the adversarial block.
6. `preferAnchoredCandidate` now computes the adversarial fork's total weight as `blockNo + 15`, potentially exceeding the honest chain's weight.
7. The node switches to the adversarial fork.

The attacker can repeat this for multiple rounds (one fake cert per round, since `PerasCertDB` deduplicates by round number), accumulating weight boosts of `15` per injected certificate across the volatile window. [6](#0-5) 

### Impact Explanation

An unprivileged peer can inject arbitrarily many fake Peras certificates (one per round number not yet present in the DB) via the object-diffusion protocol. Each accepted certificate adds `perasWeight` (default: 15) of artificial weight to an adversarial block. With `perasRoundLength = 90` slots and a volatile window of `k = 2160` blocks, an attacker can inject up to ~24 fake certificates covering the volatile window, adding up to `24 × 15 = 360` units of artificial weight to an adversarial fork. This is sufficient to make a fork that is up to 360 blocks shorter than the honest chain appear heavier, causing the node to irreversibly switch to a non-canonical chain. This constitutes a **bypass of Peras certificate/vote verification checks** enabling unauthorized certificate acceptance and a **chain selection bug** that lets an unprivileged peer make an honest node prefer a non-canonical chain. [7](#0-6) 

### Likelihood Explanation

The attack requires only a standard peer connection via the object-diffusion mini-protocol, which is publicly reachable on any Cardano node. No stake, no keys, and no privileged access are needed. The stub is in the production source path (not a test file), is wired into the live `ChainDB` and `PerasCertDB` processing pipelines, and the TODO comment confirms it is not yet replaced. Likelihood is **High**.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed committee members.
- That the claimed committee members were legitimately elected (VRF-based sortition) for the given round.
- That the total stake of the signers exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
- That `pcCertRound` is within a plausible range relative to the current slot.

Until the real implementation is in place, the object-diffusion inbound handler for `PerasCert` should reject all inbound certificates from untrusted peers, or the `PerasWeightSnapshot` should not be consulted during chain selection.

### Proof of Concept

```
1. Node N is running with Peras enabled.
2. Attacker A connects to N via the object-diffusion protocol.
3. A sends: PerasCert { pcCertRound = 999, pcCertBoostedBlock = adversarialBlockAtSlot S }
   where S is a slot in N's volatile window (between immutable tip and current tip).
4. processCerts calls validatePerasCert mkPerasParams cert → Right (ValidatedPerasCert { vpcCertBoost = 15 }).
5. PerasCertDB stores the cert; PerasWeightSnapshot gains weight 15 for adversarialBlockAtSlot S.
6. chainSelectionForBlock is triggered; preferAnchoredCandidate computes:
     adversarial fork total weight = blockNo(adversarialTip) + 15
     honest fork total weight      = blockNo(honestTip)
7. If blockNo(adversarialTip) + 15 > blockNo(honestTip), N switches to the adversarial fork.
8. Repeat for rounds 998, 997, … to accumulate more weight on the adversarial fork.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L154-177)
```haskell
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
