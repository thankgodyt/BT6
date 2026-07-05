### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Boost - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or eligibility checks whatsoever. Because this function is the sole gate used by the network-facing certificate ingest path (`processCerts`), any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block, have it accepted as "validated", and cause the receiving node to apply a chain-selection weight boost to that block — potentially making the node prefer a non-canonical or adversarial fork.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory validation entry point for inbound Peras certificates. The repository ships a single catch-all instance for all block types:

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

This stub is not confined to tests. It is the implementation used in the production network-facing ingest path. `processCerts` — called by both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` partitions the batch into valid/invalid using this callback; since the stub always returns `Right`, every certificate in every batch is classified as valid and forwarded to `addCert`: [4](#0-3) 

Once accepted, the certificate is stored in the `PerasCertDB` and immediately triggers `chainSelSync … (ChainSelAddPerasCert cert …)`, which calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

The accepted certificate's boost (`perasWeight params = PerasWeight 15` from `mkPerasParams`) is then incorporated into the `PerasWeightSnapshot` used by `preferAnchoredCandidate`. When the weight snapshot is non-empty, chain selection compares fragments by their *total weight* (length + Peras boost) rather than length alone: [6](#0-5) 

A `PerasWeight 15` boost is equivalent to 15 additional blocks of chain length, as defined in `mkPerasParams`: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` whose `pcCertBoostedBlock` points to any block on any fork — including an adversarial minority fork. Because `validatePerasCert` performs no BLS aggregate-signature verification, no quorum check, and no committee-eligibility check, the certificate is accepted unconditionally. The receiving node then applies a `PerasWeight 15` boost to the adversarial block, which can tip `preferAnchoredCandidate` into selecting the adversarial chain over the honest chain. This constitutes a **bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation**, matching the "Critical" impact tier: bypass of certificate/signature validation that enables unauthorized certificate acceptance.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is a standard peer-to-peer channel. Any node that connects as a peer can submit certificates. The stub is the only implementation in the codebase for all block types (the `StandardHash blk` catch-all instance). No additional privilege, key material, or stake is required. The attacker only needs to construct a well-formed CBOR-encoded `PerasCert` with a chosen `pcCertBoostedBlock` field, which is trivially possible given the public serialisation instances. [8](#0-7) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the BLS aggregate signature against the claimed set of committee members.
2. Checks that each claimed signer holds a valid seat in the committee for the given `PerasRoundNo` (persistent members via the epoch-start assignment; non-persistent members via their VRF eligibility proof).
3. Confirms that the aggregate stake of the signers exceeds the configured quorum threshold (`perasQuorumStakeThreshold`).

Until this is done, the `processCerts` ingest path should reject all inbound certificates (or the Peras certificate diffusion mini-protocol should be disabled entirely) to prevent the chain-selection boost from being exploitable.

---

### Proof of Concept

1. Attacker connects to a victim node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Attacker constructs a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <point on adversarial fork>`.
3. Attacker sends the certificate batch to the victim.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` unconditionally.
5. The certificate is stored in `PerasCertDB`; `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `preferAnchoredCandidate` now computes `totalWeightOfFragment` for both the honest chain and the adversarial fork. The adversarial fork gains `PerasWeight 15`, equivalent to 15 extra blocks.
7. If the adversarial fork is within 15 blocks of the honest tip, the victim node switches to the adversarial chain. [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L119-137)
```haskell
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
