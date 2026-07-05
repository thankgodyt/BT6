### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Fraudulent Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Because this function is wired directly into the Peras certificate inbound diffusion handler exposed to all node-to-node peers, any unprivileged peer can inject an arbitrary `PerasCert` that will be accepted, stored in the `PerasCertDB`, and used to boost a target block's weight in chain selection. A crafted certificate pointing to a block on a minority fork can cause an honest node to abandon the canonical chain in favor of the adversarially boosted fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The catch-all `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

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

Every certificate, regardless of content, is immediately wrapped in `Right` and returned as `ValidatedPerasCert`. No committee membership check, no quorum proof, no signature verification, no round-number sanity check is performed. [1](#0-0) 

**Inbound path — stub is wired to the live peer handler:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`. This writer is the `opwAddObjects` handler used by the production node-to-node Peras certificate diffusion client (`hPerasCertDiffusionClient`), which is registered for every connected peer. [2](#0-1) [3](#0-2) 

**`processCerts` — accepts and stores any cert that passes the stub:**

`processCerts` calls `validateCert` on each inbound certificate. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`. [4](#0-3) 

**Chain selection — fraudulent cert triggers a fork switch:**

`chainSelSync` processes the newly added certificate. It reads the `PerasWeightSnapshot` (which now includes the fraudulent boost), looks up the boosted block in the VolatileDB, and calls `chainSelectionForBlock` for it. Chain selection then compares the total weight of the boosted fork against the current chain using `preferAnchoredCandidate`, which adds `perasWeight = 15` to the fork's score. [5](#0-4) [6](#0-5) 

**Weight boost magnitude:**

`mkPerasParams` sets `perasWeight = PerasWeight 15`. A single fraudulent certificate therefore makes a fork that is up to 15 blocks shorter than the current chain appear heavier, sufficient to trigger a chain switch. [7](#0-6) 

**Exploit sequence:**

1. Attacker connects to a victim node as a normal peer.
2. Attacker sends a `PerasCert` via the Peras certificate diffusion mini-protocol with `pcCertBoostedBlock` pointing to the tip of a minority fork present in the victim's VolatileDB.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is added to the `PerasCertDB`; the `PerasWeightSnapshot` is updated to give the minority fork's tip a boost of 15.
5. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `preferAnchoredCandidate` computes `wsvTotalWeight` for both chains; the boosted fork wins if it is within 15 blocks of the current tip.
7. The victim node rolls back to the minority fork, abandoning the canonical chain.

---

### Impact Explanation

This is a **High** severity chain-selection bug. An unprivileged peer with a single network connection can cause an honest node to prefer a non-canonical, adversarially chosen chain over the honest chain. The Peras weight boost is designed to be large enough to override the longest-chain rule for short forks; a fraudulent certificate exploits exactly this property. The node's view of the canonical chain diverges from the rest of the network, breaking consensus safety for that node without any stake majority or key compromise.

---

### Likelihood Explanation

The attack requires only a standard node-to-node connection. The Peras certificate diffusion mini-protocol is enabled and exposed to all peers. The attacker needs no special privileges, no cryptographic keys, and no stake. The only precondition is that the target block exists in the victim's VolatileDB (i.e., the victim has already downloaded the fork's headers/blocks via ChainSync/BlockFetch). This is a realistic and easily satisfied condition during normal network operation.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's committee membership proof (that the signers were legitimately selected for the round).
- The aggregate signature over the certified block and round number.
- That the round number is within the valid range relative to the current slot.
- That the boosted block's slot satisfies `perasBlockMinSlots`.

Until real validation is implemented, the inbound Peras certificate diffusion handler (`hPerasCertDiffusionClient`) should be disabled or should reject all inbound certificates rather than accepting them unconditionally. [8](#0-7) 

---

### Proof of Concept

```
Attacker node  ──[PerasCert { pcCertRound=R, pcCertBoostedBlock=<fork tip> }]──►  Victim node
                                                                                       │
                                                                          processCerts │
                                                                  validatePerasCert ──►│ always Right
                                                                                       │
                                                                    addPerasCertAsync ─►│ stored in PerasCertDB
                                                                                       │
                                                                     chainSelSync ─────►│ reads PerasWeightSnapshot
                                                                                       │   fork tip weight += 15
                                                                chainSelectionForBlock ─►│ fork wins if ≤15 blocks shorter
                                                                                       │
                                                                  Victim rolls back ◄──┘ to adversarial fork
```

The `processCerts` function at line 168 of `PerasCert.hs` calls `validateCert <$> certsNotAlreadyInDb`; since `validatePerasCert` always returns `Right`, `partitionEithers` always produces `([], validatedCerts)`, and every certificate is unconditionally added to the ChainDB. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L61-87)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
