### Title
Unvalidated Peras Certificate Injection Inflates Chain-Selection Weight — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

The Peras chain-selection weight is computed directly from every certificate stored in `PerasCertDB`. Because `validatePerasCert` is a no-op stub that unconditionally returns `Right` and `implAddCert` performs no content validation, an unprivileged peer can inject crafted certificates via the `ObjectDiffusion` mini-protocol to boost arbitrary blocks. The resulting inflated `PerasWeightSnapshot` is consumed by both `preferCandidate` (chain selection) and `takeVolatileSuffix` (immutability boundary), allowing the attacker to steer an honest node onto a non-canonical chain or to prematurely freeze the rollback window.

---

### Finding Description

**Vulnerability class:** Chain-selection error via unvalidated external state injection — direct analog of the StHEU exchange-rate manipulation where `totalHEU = heu.balanceOf(address(this))` could be inflated by direct transfers bypassing `lock()`.

**Root cause 1 — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The catch-all `StandardHash blk => BlockSupportsPeras blk` instance unconditionally returns `Right` for every certificate, performing zero cryptographic or quorum checks. The `vpcCertBoost` is set to the local config value `perasWeight params`, not derived from the certificate itself.

**Root cause 2 — `implAddCert` performs no content validation:** [2](#0-1) 

The only deduplication check is whether a certificate for the same `PerasRoundNo` already exists. No validation of the boosted block's existence, the certificate's quorum, or any cryptographic property is performed. The TODO comment explicitly acknowledges missing "non-trivial validation logic."

**Weight snapshot is built directly from stored certificates:** [3](#0-2) 

`implGetWeightSnapshot` maps every stored certificate to `(getPerasCertBoostedBlock cert, getPerasCertBoost cert)` with no further filtering. This is the direct analog of `totalHEU = heu.balanceOf(address(this))` — the weight is derived from an observable store that can be populated by external input.

**Weight snapshot drives both chain selection and immutability boundary:** [4](#0-3) [5](#0-4) 

`preferCandidate` compares `wsvTotalWeight` (block count + weight boost) to decide which chain to adopt. `takeVolatileSuffix` uses the same snapshot to determine which blocks are buried under weight `k` and therefore immutable.

**`getCurrentChainLike` feeds the snapshot directly into `takeVolatileSuffix`:** [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can send one crafted `PerasCert` per `PerasRoundNo`. Each accepted certificate adds `perasWeight params` of boost to the attacker's chosen block. With enough rounds, the attacker's chain fragment accumulates total weight exceeding the honest chain's weight, causing `preferCandidate` to return `ShouldSwitch` and the node to adopt the attacker's chain. Separately, by boosting recent blocks on the current chain, the attacker can push `takeVolatileSuffix` to shrink the volatile window, prematurely treating blocks as immutable and preventing legitimate rollback to a better honest chain.

**Impact category:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The `ObjectDiffusion` mini-protocol for Peras certificates is a public-facing network endpoint. Any peer that can establish a connection can submit certificates. The degenerate `validatePerasCert` instance is the only instance in the codebase (the Cardano-specific instance is not yet implemented), so it is the code path executed in any deployment of this codebase. The attack requires only sending one certificate message per round — no stake, no keys, no special privileges.

---

### Recommendation

1. **Implement real certificate validation in `validatePerasCert`**: verify the quorum of committee member signatures, that the boosted block exists on a known valid chain, and that the round number is within the expected window.

2. **Add content validation in `implAddCert`**: even after `validatePerasCert`, `implAddCert` should verify that the `getPerasCertBoostedBlock` point is within the volatile window and that the certificate is not equivocating (same round, different block) before storing it.

3. **Track only internally-verified boosts**: analogous to the StHEU recommendation of using `totalLockedHEU` instead of `balanceOf`, maintain a separate validated set of boosts that only grows through fully-verified certificate acceptance, rather than deriving the weight snapshot from the raw certificate store.

---

### Proof of Concept

1. Peer connects and sends a `PerasCert` with `pcCertRound = PerasRoundNo N` and `pcCertBoostedBlock = blockPoint <attacker_block>` for any block on the attacker's fork.
2. The node calls `validatePerasCert params cert` → always returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
3. `implAddCert` checks `Set.member N pcdsCertIds` → `False` (first cert for this round) → stores the certificate.
4. `implGetWeightSnapshot` builds `PerasWeightSnapshot` including `(blockPoint <attacker_block>, perasWeight params)`.
5. `getCurrentChainLike` calls `takeVolatileSuffix weights k curChain` — if the attacker's fragment now has higher `wsvTotalWeight` than the honest fragment, `preferCandidate` returns `ShouldSwitch (Heavier ...)` and the node switches to the attacker's chain.
6. Repeat for rounds `N+1, N+2, …` to accumulate sufficient weight advantage. [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-214)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs (L100-159)
```haskell
-- | Return the last @k@ headers.
--
-- While the in-memory fragment ('cdbChain') might temporarily have more weight
-- than @k@ (until the background thread has copied those blocks to the
-- ImmutableDB), this function will never return a fragment heavier than @k@.
--
-- The anchor point of the returned fragment will be the most recent
-- \"immutable\" block, i.e. a block that cannot be rolled back. In
-- ChainDB.md, we call this block @i@.
--
-- Note that the returned fragment may have weight less than @k@ in case the
-- whole chain itself weights less than @k@, or in case the VolatileDB was
-- corrupted. In the latter case, we don't take blocks already in the
-- ImmutableDB into account, as we know they /must/ have been \"immutable\" at
-- some point, and, therefore, /must/ still be \"immutable\".
getCurrentChain ::
  forall m blk.
  ( IOLike m
  , StandardHash blk
  , HasHeader (Header blk)
  , ConsensusProtocol (BlockProtocol blk)
  ) =>
  ChainDbEnv m blk ->
  STM m (AnchoredFragment (Header blk))
getCurrentChain cdb@CDB{..} =
  getCurrentChainLike cdb $ icWithoutTime <$> readTVar cdbChain

-- | Same as 'getCurrentChain', /mutatis mutandi/.
getCurrentChainWithTime ::
  forall m blk.
  ( IOLike m
  , StandardHash blk
  , HasHeader (Header blk)
  , ConsensusProtocol (BlockProtocol blk)
  , Typeable blk
  ) =>
  ChainDbEnv m blk ->
  STM m (AnchoredFragment (HeaderWithTime blk))
getCurrentChainWithTime cdb@CDB{..} =
  getCurrentChainLike cdb $ icWithTime <$> readTVar cdbChain

-- | This function is the generalised helper for 'getCurrentChain' and
-- 'getCurrentChainWithTime'. See 'getCurrentChain' for the explanation of it's
-- behaviour.
getCurrentChainLike ::
  forall m blk h.
  ( IOLike m
  , StandardHash blk
  , HasHeader h
  , HeaderHash blk ~ HeaderHash h
  , ConsensusProtocol (BlockProtocol blk)
  ) =>
  ChainDbEnv m blk ->
  STM m (AnchoredFragment h) ->
  STM m (AnchoredFragment h)
getCurrentChainLike cdb@CDB{..} getCurChain = do
  weights <- forgetFingerprint <$> getPerasWeightSnapshot cdb
  takeVolatileSuffix weights k <$> getCurChain
 where
  k = configSecurityParam cdbTopLevelConfig
```
