### Title
Missing Era-Enforcement Check in `validatePerasCert` Allows Fraudulent Peras Certificate Injection to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (valid) for every peer-supplied Peras certificate, without checking whether Peras is actually enabled for the era the certificate claims to be from, and without performing any cryptographic or structural validation. This is directly analogous to the reported bug: a peer-supplied parameter (the certificate) is consumed without enforcing the protocol-level constraint that should govern it (era-level Peras enablement). When Peras is active, an unprivileged peer can inject crafted certificates that apply weight boosts to arbitrary blocks, causing chain selection to prefer a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` degenerate instance:** [1](#0-0) 

The instance is explicitly marked as a placeholder for all block types:

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
```

Every certificate, regardless of its round number, boosted block, or whether Peras is enabled for the relevant era, is accepted and assigned a weight boost of `perasWeight params`. No check is made against `eraPerasRoundLength` (the optional `PerasEnabled PerasRoundLength` field in `EraParams`) to confirm that the certificate's claimed round belongs to a Peras-enabled era. [2](#0-1) 

**Inbound path — `processCerts` in the object diffusion mini-protocol:** [3](#0-2) 

`processCerts` calls `validatePerasCert mkPerasParams` on every inbound certificate batch. Because the degenerate instance always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`. [4](#0-3) 

**Storage — `implAddCert` performs no era-based validation:** [5](#0-4) 

The only deduplication check is whether the round number is already present. No check is made against the era summary to confirm the round number falls within a Peras-enabled era.

**Chain selection — weight boosts from injected certificates are applied unconditionally:** [6](#0-5) 

When `isEmptyPerasWeightSnapshot weights` is `False` (i.e., Peras is active and at least one certificate has been stored), `preferAnchoredCandidate` and `compareAnchoredFragments` switch to the weighted path, applying `weightBoostOfFragment` over the injected snapshot. A fraudulent certificate boosting a block on an adversarial fork directly inflates that fork's `wsvTotalWeight`. [7](#0-6) 

**Chain selection trigger — `chainSelSync` re-runs selection for the boosted block:** [8](#0-7) 

After a certificate is stored, `chainSelSync` triggers `chainSelectionForBlock` for the boosted block. If the adversarial fork's total weight now exceeds the honest chain's, the node switches.

---

### Impact Explanation

**Classification: High — chain selection bug enabling non-canonical chain preference.**

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to a block on an adversarial fork.
2. Send it via the node-to-node object diffusion mini-protocol.
3. `validatePerasCert` unconditionally accepts it; `implAddCert` stores it.
4. `implGetWeightSnapshot` includes the fraudulent boost in the `PerasWeightSnapshot`.
5. `preferAnchoredCandidate` now computes a higher `wsvTotalWeight` for the adversarial fork.
6. The honest node switches to the adversarial fork, abandoning the canonical chain.

This directly violates the chain selection invariant: the node prefers a chain it should not, based on a certificate that was never legitimately produced by a quorum of Peras committee members.

---

### Likelihood Explanation

**Medium.** Peras is disabled by default (`eraPerasRoundLength = NoPerasEnabled`), so the vulnerability is dormant on current mainnet. However, the object diffusion mini-protocol for Peras certificates is already wired into the production node code path. Once Peras is enabled on any network (testnet or mainnet), any peer connected via node-to-node can exploit this with a single crafted certificate message. No keys, stake, or privileged access are required.

---

### Recommendation

In `validatePerasCert`, before accepting a certificate, verify:

1. The certificate's round number maps to a slot range within a Peras-enabled era (using the hard fork summary query `slotToPerasRoundNo` / `perasRoundNoToSlot`).
2. The certificate carries a valid quorum signature from the Peras committee for that round.
3. The boosted block's slot falls within the candidate window defined by the era's `eraPerasRoundLength`.

Until real validation is implemented, the `processCerts` inbound handler should reject all certificates when Peras validation is not yet available, rather than silently accepting them. The existing `PerasCertInboundException` mechanism is already in place to disconnect misbehaving peers. [9](#0-8) 

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Unprivileged peer
  → node-to-node object diffusion mini-protocol
  → opwAddObjects [craftedCert]          -- PerasCert.hs:121-133
  → processCerts ... (validatePerasCert mkPerasParams) ... [craftedCert]
  → validatePerasCert params craftedCert -- SupportsPeras.hs:353-358
      = Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
  → ChainDB.addPerasCertAsync craftedCert
  → chainSelSync (ChainSelAddPerasCert craftedCert ...)
  → PerasCertDB.addCert cdbPerasCertDB craftedCert  -- no era check
  → chainSelectionForBlock cdb ... boostedHdr        -- re-runs chain sel
  → preferAnchoredCandidate cfg weights ours cand    -- weighted path
      where weights contains fraudulent boost for adversarial fork block
  → ShouldSwitch (adversarial fork now heavier)
```

**Crafted certificate structure:**

```haskell
craftedCert = PerasCert
  { pcCertRound        = PerasRoundNo <any round number>
  , pcCertBoostedBlock = blockPoint <tip of adversarial fork>
  }
```

`validatePerasCert` returns `Right` unconditionally. The boost `perasWeight params` is added to the adversarial fork's `wsvTotalWeight`. If the adversarial fork's total weight exceeds the honest chain's, `chainSelectionForBlock` switches the node's selection to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EraParams.hs (L142-149)
```haskell
data EraParams = EraParams
  { eraEpochSize :: !EpochSize
  , eraSlotLength :: !SlotLength
  , eraSafeZone :: !SafeZone
  , eraGenesisWin :: !GenesisWindow
  , eraPerasRoundLength :: !(PerasEnabled PerasRoundLength)
  -- ^ Optional, as not every era will be Peras-enabled
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L139-144)
```haskell
data PerasCertInboundException
  = forall blk. PerasCertValidationError [PerasValidationErr blk]

deriving instance Show PerasCertInboundException

instance Exception PerasCertInboundException
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
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
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L143-149)
```haskell
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
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
