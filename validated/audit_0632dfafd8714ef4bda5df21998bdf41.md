### Title
Stub `validatePerasCert` Always Accepts Any Certificate, Enabling Unbounded Peras Weight Inflation via Crafted Network Messages - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` typeclass instance contains a stub `validatePerasCert` that unconditionally returns `Right` for every inbound `PerasCert`, bypassing all cryptographic and semantic checks. An unprivileged peer can exploit this by sending many crafted certificates for distinct round numbers, all boosting the same block point. Because `implGetWeightSnapshot` sums the boost of every stored certificate, the `PerasWeightSnapshot` for that block grows without bound. The inflated snapshot is then consumed directly by chain selection (`preferAnchoredCandidate`, `compareAnchoredFragments`) and by the immutability boundary computation (`takeVolatileSuffix`), allowing the attacker to either force the node to prefer a non-canonical fork or to prematurely advance the immutable tip, permanently preventing legitimate rollbacks.

---

### Finding Description

**Step 1 – Validation stub always succeeds.**

The `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasCert` as a trivial stub:

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

Every `PerasCert` received from any peer is accepted and assigned the full configured boost weight. [1](#0-0) 

**Step 2 – Inbound certificates reach the DB without further checks.**

`processCerts` in the object-diffusion layer calls `validateCert` (bound to `validatePerasCert mkPerasParams`) and, if all certs pass, adds them to the `PerasCertDB`. Because the stub always returns `Right`, every crafted certificate is stored. [2](#0-1) 

**Step 3 – Deduplication is by round number only.**

`implAddCert` deduplicates on `PerasRoundNo`. An attacker can send N certificates for N distinct round numbers, all with `pcCertBoostedBlock` pointing to the same block. Each is stored as a separate entry in `pcdsCertsByTicket`. [3](#0-2) 

**Step 4 – Weight snapshot sums all stored boosts for a point.**

`implGetWeightSnapshot` iterates over every stored certificate and calls `mkPerasWeightSnapshot`, which uses `addToPerasWeightSnapshot` with `Map.insertWith (<>)`. If N certificates all name the same block, the resulting `PerasWeight` for that point is `N × perasWeight params`. [4](#0-3) [5](#0-4) 

**Step 5 – Inflated snapshot drives chain selection.**

`chainSelectionForBlock` reads the weight snapshot atomically and passes it to `constructPreferableCandidates` and `switchTo`. `preferAnchoredCandidate` compares `wsvTotalWeight` values; an attacker-inflated boost on a fork's blocks makes that fork appear heavier than the honest chain. [6](#0-5) 

**Step 6 – Inflated snapshot shrinks the volatile suffix.**

`getCurrentChainLike` calls `takeVolatileSuffix weights k` on the current chain. `takeVolatileSuffix` returns the longest suffix whose `totalWeightOfFragment` is `≤ k`. If the attacker inflates the weight of blocks on the honest chain, the volatile suffix shrinks: fewer blocks remain rollback-able, and more blocks are prematurely moved to the ImmutableDB. [7](#0-6) [8](#0-7) 

---

### Impact Explanation

There are two concrete impacts:

1. **Chain selection hijack (High).** By sending many certificates boosting blocks on an attacker-controlled fork, the attacker inflates that fork's `wsvTotalWeight`. `preferAnchoredCandidate` then returns `ShouldSwitch` for the fork, causing the node to adopt a non-canonical chain. This matches the "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" criterion. [9](#0-8) 

2. **Premature immutability / rollback prevention (High).** By boosting blocks on the honest chain, the attacker shrinks the volatile suffix below `k` blocks. Blocks that should still be rollback-able are copied to the ImmutableDB. If the honest chain later needs to roll back past the artificially advanced immutable tip, the node cannot do so, permanently locking it onto a potentially wrong chain. [10](#0-9) 

---

### Likelihood Explanation

The attack path is fully reachable by any unprivileged peer connected via the object-diffusion mini-protocol. No stake, keys, or operator access is required. The attacker only needs to craft `PerasCert` messages with distinct `PerasRoundNo` values and a chosen `pcCertBoostedBlock`. Because `validatePerasCert` is a stub that always returns `Right`, there is no cryptographic barrier. The number of certificates needed to exceed `k` weight is bounded by `k / perasWeight params`, which is a small constant on mainnet (e.g., `k=2160`, `perasWeight≈15` → ~144 certificates). [11](#0-10) 

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`. At minimum, verify the aggregate BLS signature, check that the round number is within the current epoch's valid range, verify that the boosted block point exists on a known chain, and confirm that the quorum threshold was actually met by the claimed voters. The `V1.hs` concrete certificate type already carries the necessary fields (`pcSignature`, `pcVoters`). [12](#0-11) 

2. **Cap the weight contribution per block point** in `implGetWeightSnapshot`. The Peras protocol specifies at most one certificate per round; the weight for any single block point should be bounded by `perasWeight × (number of valid rounds)`, not by the number of certificates an attacker can inject. [4](#0-3) 

3. **Enforce equivocation rejection** at the DB level: if two certificates for the same round boost different blocks, reject the second one rather than storing it. [3](#0-2) 

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  sends via object-diffusion mini-protocol:
  │    PerasCert { pcCertRound = 1, pcCertBoostedBlock = <fork_tip> }
  │    PerasCert { pcCertRound = 2, pcCertBoostedBlock = <fork_tip> }
  │    ...
  │    PerasCert { pcCertRound = N, pcCertBoostedBlock = <fork_tip> }
  │
  ▼
processCerts
  └─ validatePerasCert mkPerasParams cert  →  always Right (stub)
  └─ addCert (each cert stored, different roundNo)

implGetWeightSnapshot
  └─ mkPerasWeightSnapshot [(fork_tip, boost), (fork_tip, boost), ...]
  └─ weight(fork_tip) = N × perasWeight params   ← inflated

chainSelectionForBlock
  └─ preferAnchoredCandidate bcfg weights curChain forkFragment
  └─ wsvTotalWeight(fork) = blockNo + N×boost  >>  wsvTotalWeight(honest)
  └─ ShouldSwitch  →  node adopts attacker's fork

-- OR --

takeVolatileSuffix weights k honestChain
  └─ totalWeightOfFragment(honestChain) = length + N×boost  >>  k
  └─ volatile suffix = []  (all blocks considered immutable)
  └─ node cannot roll back; honest chain blocks prematurely finalized
```

The attack requires sending `⌈k / perasWeight⌉` certificates (e.g., ~144 for mainnet parameters), all of which pass the stub validator unconditionally. [13](#0-12) [14](#0-13)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L319-377)
```haskell
-- | Take the longest suffix of the given fragment with total weight
-- ('totalWeightOfFragment') at most @k@. This is the volatile suffix of blocks
-- which are subject to rollback.
--
-- If the total weight of the input fragment is at least @k@, then the anchor of
-- the output fragment is the most recent point on the input fragment that is
-- buried under at least weight @k@ (also counting the weight boost of that
-- point).
--
-- See 'mkPerasWeightSnapshot' for context.
--
-- >>> :{
-- weights :: [(Point Blk, PerasWeight)]
-- weights =
--   [ (BlockPoint 2 "foo", PerasWeight 2)
--   , (GenesisPoint,       PerasWeight 3)
--   , (BlockPoint 3 "bar", PerasWeight 2)
--   , (BlockPoint 2 "foo", PerasWeight 2)
--   ]
-- snap = mkPerasWeightSnapshot weights
-- foo = HeaderFields (SlotNo 2) (BlockNo 1) "foo"
-- bar = HeaderFields (SlotNo 3) (BlockNo 2) "bar"
-- frag :: AnchoredFragment (HeaderFields Blk)
-- frag = Empty AnchorGenesis :> foo :> bar
-- :}
--
-- >>> k1 = SecurityParam $ knownNonZeroBounded @1
-- >>> k3 = SecurityParam $ knownNonZeroBounded @3
-- >>> k6 = SecurityParam $ knownNonZeroBounded @6
-- >>> k9 = SecurityParam $ knownNonZeroBounded @9
--
-- >>> AF.toOldestFirst $ takeVolatileSuffix snap k1 frag
-- []
--
-- >>> AF.toOldestFirst $ takeVolatileSuffix snap k3 frag
-- [HeaderFields {headerFieldSlot = SlotNo 3, headerFieldBlockNo = BlockNo 2, headerFieldHash = "bar"}]
--
-- >>> AF.toOldestFirst $ takeVolatileSuffix snap k6 frag
-- [HeaderFields {headerFieldSlot = SlotNo 3, headerFieldBlockNo = BlockNo 2, headerFieldHash = "bar"}]
--
-- >>> AF.toOldestFirst $ takeVolatileSuffix snap k9 frag
-- [HeaderFields {headerFieldSlot = SlotNo 2, headerFieldBlockNo = BlockNo 1, headerFieldHash = "foo"},HeaderFields {headerFieldSlot = SlotNo 3, headerFieldBlockNo = BlockNo 2, headerFieldHash = "bar"}]
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-686)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

  -- The current chain we're working with here is not longer than @k@ blocks
  -- (see 'getCurrentChain' and 'cdbChain'), which is easier to reason about
  -- when doing chain selection, etc.
  assert (fromIntegral (AF.length curChain) <= unNonZero k) pure ()

  let
    immBlockNo :: WithOrigin BlockNo
    immBlockNo = AF.anchorBlockNo curChain

  if
    -- The chain might have grown since we added the block such that the
    -- block is older than the immutable tip.
    | olderThanImmTip hdr immBlockNo -> do
        traceWith addBlockTracer $ IgnoreBlockOlderThanImmTip p

    -- The block is invalid
    | Just (InvalidBlockInfo reason _) <- Map.lookup (headerHash hdr) invalid -> do
        traceWith addBlockTracer $ IgnoreInvalidBlock p reason

        -- We wouldn't know the block is invalid if its prefix was invalid,
        -- hence 'InvalidBlockPunishment.BlockItself'.
        InvalidBlockPunishment.enact
          punish
          InvalidBlockPunishment.BlockItself

    -- Try to select a chain involving the block.
    | otherwise -> do
        -- Construct all 'ChainDiff's involving the block.
        chainDiffs <-
          constructPreferableCandidates
            cdb
            weights
            curChain
            (Map.singleton (headerHash hdr) hdr)
            (headerRealPoint hdr)

        let traceNoChange = traceWith addBlockTracer $ StoreButDontChange p

            chainSelEnv = mkChainSelEnv cdb blockCache weights curChain (Just (p, punish))

        case NE.nonEmpty chainDiffs of
          Just chainDiffs' -> do
            -- Find the best valid candidate and, if valid, perform a
            -- switch. Log if none were found.
            flip whenNothing traceNoChange
              =<< chainSelection
                chainSelEnv
                chainDiffs'
                (switchTo cdb weights (Just p))
          -- No candidate better than our chain.
          Nothing -> traceNoChange
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L155-159)
```haskell
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-60)
```haskell
-- | Concrete Peras certificates using BLS signatures
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
```
