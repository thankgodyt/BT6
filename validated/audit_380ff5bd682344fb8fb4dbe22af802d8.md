### Title
Unconditional Peras Certificate Acceptance Enables Unauthorized Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally accepts every inbound Peras certificate without performing any cryptographic, quorum, or committee-membership check. Because accepted certificates are immediately fed into chain selection and grant arbitrary weight boosts to attacker-chosen blocks, an unprivileged peer can force an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must be passed before a certificate influences chain selection. The sole production instance (the "degenerate instance for all blks", the only one that exists) implements this gate as an unconditional `Right`:

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

No signature is verified, no quorum threshold is checked, and no committee membership is confirmed. The `PerasCert` data type carries only a round number and a block point — both fully attacker-controlled over the wire:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

The inbound certificate processing path in `processCerts` calls `validatePerasCert mkPerasParams` on every new certificate received from a peer, and on success immediately stores it and triggers chain selection: [3](#0-2) [4](#0-3) 

Once stored, `chainSelSync` processes the certificate via `addPerasCertAsync`, looks up the boosted block in the VolatileDB, and calls `chainSelectionForBlock` for it: [5](#0-4) 

Chain selection then uses `preferAnchoredCandidate`, which — when the `PerasWeightSnapshot` is non-empty — computes `weightBoostOfFragment` for each candidate suffix and compares total weights: [6](#0-5) [7](#0-6) 

The weight boost is additive and unbounded per round (the `PerasWeightSnapshot` accumulates all boosts for a point): [8](#0-7) 

An attacker who sends a certificate pointing to any block in the VolatileDB of the victim node will cause that block to receive a `perasWeight` boost (default: `PerasWeight 15`, equivalent to 15 extra blocks of chain length) and potentially trigger a chain switch.

---

### Impact Explanation

This is a **High** chain-selection bug. An unprivileged peer can craft a `PerasCert` message naming any block hash it knows (e.g., from a previously diffused header) as `pcCertBoostedBlock`. The victim node will:

1. Accept the certificate unconditionally.
2. Add a `PerasWeight 15` boost to the named block.
3. Re-run chain selection, potentially switching to a fork that would otherwise be rejected as shorter/lighter.

Because the boost is permanent in the `PerasCertDB` for that round, and because the `PerasWeightSnapshot` is used in all subsequent chain comparisons, the attacker can persistently tilt chain selection toward a non-canonical fork. With multiple crafted certificates across different rounds, the cumulative boost can exceed any honest chain's length advantage within the volatile window.

---

### Likelihood Explanation

The Peras certificate object-diffusion mini-protocol is reachable by any connected peer. The attack requires only knowledge of a block hash in the victim's VolatileDB (obtainable via ChainSync headers) and the ability to send a single well-formed CBOR-encoded `PerasCert` message. No key material, stake, or privileged access is needed. The `PerasCert` serialization format is public and trivially constructable. [9](#0-8) 

---

### Recommendation

The `validatePerasCert` stub must be replaced with a real implementation before the Peras certificate diffusion path is enabled in production. At minimum it must verify:

1. **Aggregate BLS signature** over `(pcCertRound, pcCertBoostedBlock)` against the aggregated public keys of the claimed committee members (as already implemented for the `WFALS` and `EveryoneVotes` committee schemes in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs`).
2. **Quorum threshold**: the total stake of the signers must satisfy `stakeAboveThreshold` with a correctly normalized `PerasVoteStake`.
3. **Committee membership**: each claimed signer must be a valid member of the committee for the given round.

The existing `verifyCert` method on the `VotingCommittee` typeclass already provides this logic for the concrete committee implementations and should be wired into `validatePerasCert`. [10](#0-9) 

---

### Proof of Concept

An attacker connected to a victim node via the Peras certificate object-diffusion mini-protocol:

1. Observes a block hash `H` at slot `S` from the victim's ChainSync stream (a block on a competing fork).
2. Constructs a `PerasCert` with `pcCertRound = R` (any unused round) and `pcCertBoostedBlock = BlockPoint S H`.
3. Serializes it as CBOR (3-field list: round `Word64`, slot `Word64`, hash `Bytes32`) and sends it.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
5. The cert is stored; `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` finds block `H` in the VolatileDB, calls `chainSelectionForBlock` for it.
7. `preferAnchoredCandidate` now sees the fork containing `H` with `wsvWeightBoost += 15`; if the fork was within 15 blocks of the honest tip, the node switches to it. [11](#0-10) [12](#0-11)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L208-213)
```haskell
weightBoostOfPoint ::
  forall blk.
  StandardHash blk =>
  PerasWeightSnapshot blk -> Point blk -> PerasWeight
weightBoostOfPoint (PerasWeightSnapshot weightByPoint) pt =
  Map.findWithDefault mempty pt weightByPoint
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L116-122)
```haskell
  -- | Verify a certificate attesting the winner of a given election
  verifyCert ::
    VotingCommittee crypto committee ->
    Cert crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (NE [EligibilityWitness crypto committee])
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-177)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
