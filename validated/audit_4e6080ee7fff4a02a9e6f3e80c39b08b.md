### Title
Unvalidated Peras Certificate Acceptance Inflates Chain Weight, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally accepts every inbound certificate (`Right` always). An unprivileged peer can therefore send arbitrarily crafted `PerasCert` messages via the ObjectDiffusion mini-protocol, inject them into the `PerasCertDB`, and inflate the Peras weight of any block in the VolatileDB. Because chain selection and the immutability boundary both consume the resulting `PerasWeightSnapshot` without any independent verification, the attacker can make an honest node prefer a non-canonical chain or shift the immutability boundary, breaking consensus safety.

---

### Finding Description

**Vulnerability class (analog to M-27):** In M-27, LP position value is computed from manipulable pool reserves plus a trusted oracle price; the invariant `x·y=k` guarantees the computed value can only be *inflated*, never deflated, enabling an attacker to over-collateralise a loan. Here, Peras chain weight is computed from block count (trusted) plus a weight boost drawn from the `PerasWeightSnapshot` (manipulable via unauthenticated certificates); the snapshot can only be *inflated* by injecting fraudulent certificates, enabling an attacker to make their chain appear heavier than the honest chain.

**Root cause — stub `validatePerasCert`:** [1](#0-0) 

The degenerate instance (lines 318–358) is the only concrete `BlockSupportsPeras` instance in the repository. Its `validatePerasCert` always returns `Right`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No signature check, no committee membership check, no quorum check, no round-validity check.

**Network entry path — ObjectDiffusion inbound handler:** [2](#0-1) 

Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` call `validatePerasCert mkPerasParams` (the stub) on every peer-supplied `PerasCert`. Because the stub never rejects, `processCerts` timestamps and stores every certificate: [3](#0-2) 

**Storage — `implAddCert` deduplicates only by round number:** [4](#0-3) 

The only guard is `Set.member roundNo (pcdsCertIds pcds)`. An attacker can submit one fraudulent certificate per round number, accumulating an unbounded number of weight boosts across distinct rounds.

**Weight snapshot construction — all stored certs contribute:** [5](#0-4) 

`implGetWeightSnapshot` maps every stored `ValidatedPerasCert` to `(getPerasCertBoostedBlock cert, getPerasCertBoost cert)` with no further validation. Fraudulent entries are indistinguishable from legitimate ones.

**Chain selection — total weight drives `preferCandidate`:** [6](#0-5) 

`wsvTotalWeight = BlockNo + PerasWeight(boost)`. `preferCandidate` switches to the candidate chain whenever `wsvTotalWeight cand > wsvTotalWeight ours`. Fraudulent boosts on the attacker's chain directly increase `wsvTotalWeight cand`.

**Immutability boundary — `takeVolatileSuffix` uses the same snapshot:** [7](#0-6) 

`takeVolatileSuffix` calls `totalWeightOfFragment snap` to find the longest suffix with weight ≤ k. Inflating the weight of the attacker's chain shifts the immutability boundary, potentially causing blocks that should remain volatile to be treated as immutable, preventing rollback to the honest chain.

---

### Impact Explanation

An unprivileged peer can:

1. Send valid blocks (which pass normal block validation) to populate the VolatileDB.
2. Send fraudulent `PerasCert` messages (one per round number) boosting those blocks. Each certificate adds `perasWeight params` to the block's entry in the `PerasWeightSnapshot`.
3. After accumulating enough fraudulent boosts, `wsvTotalWeight` of the attacker's chain exceeds that of the honest chain, causing `preferCandidate` to return `ShouldSwitch` and the node to adopt the attacker's chain.
4. Additionally, `takeVolatileSuffix` computes an incorrect immutability boundary for the attacker's chain, potentially marking attacker blocks as immutable and blocking any subsequent rollback to the honest chain.

This satisfies the **High** impact criterion: a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

- The ObjectDiffusion mini-protocol for Peras certificates is a standard peer-to-peer channel; any connected peer can send `PerasCert` messages.
- No cryptographic material is required: the stub `validatePerasCert` accepts any `(roundNo, boostedBlock)` pair.
- The only deduplication is by round number, so the attacker can submit one certificate per round, accumulating boosts proportional to the number of rounds elapsed.
- The attack requires the attacker to also have valid blocks in the VolatileDB (so that `weightBoostOfFragment` counts the boost), but sending valid blocks is the normal operation of any peer.

---

### Recommendation

1. **Implement real `validatePerasCert`**: The stub at `SupportsPeras.hs` lines 350–358 must be replaced with a concrete implementation that verifies the certificate's BLS aggregate signature, checks committee membership against the current stake distribution, and confirms the quorum threshold is met. The `PerasValidationErr` type should enumerate all failure modes.

2. **Verify boosted block exists on a known valid chain**: Before storing a certificate, confirm that `pcCertBoostedBlock` refers to a block that has been validated by the ledger, not merely any hash a peer supplies.

3. **Enforce the `implAddCert` TODO**: The comment at line 167 of `PerasCertDB/Impl.hs` acknowledges missing validation. Until real validation is in place, the `PerasCertDB` should not be reachable from the network-facing ObjectDiffusion handler.

4. **Bound the weight boost per chain**: Consider capping the total weight boost attributable to certificates not yet confirmed by the immutable ledger state, analogous to how the LP value fix in M-27 recomputes value at the "correct" reserve ratio rather than the manipulated one.

---

### Proof of Concept

```
Attacker node A connects to honest node H.

1. A sends valid blocks B1, B2, ..., Bn extending a fork from H's chain.
   H stores them in VolatileDB (they pass normal header/block validation).

2. A sends PerasCert { pcCertRound = 1, pcCertBoostedBlock = point(B1) }
   processCerts calls validatePerasCert mkPerasParams → Right (always)
   implAddCert stores it; PerasWeightSnapshot gains +perasWeight for B1.

3. A repeats for rounds 2..n, boosting B2..Bn.
   PerasWeightSnapshot now has +n*perasWeight on A's fork.

4. Chain selection runs:
   wsvTotalWeight(A's fork) = n + n*perasWeight  (blocks + boosts)
   wsvTotalWeight(H's chain) = n                 (blocks only, no certs)
   preferCandidate returns ShouldSwitch → H adopts A's non-canonical fork.

5. takeVolatileSuffix on A's fork computes total weight >> k,
   marking A's blocks as immutable; H can no longer roll back to the honest chain.
``` [8](#0-7) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
