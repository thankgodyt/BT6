### Title
Peras Certificate Validation Bypass Allows Arbitrary Chain Weight Inflation via Stub `validatePerasCert` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a no-op stub that unconditionally accepts every inbound certificate and assigns it the full configured `perasWeight` boost. This stub is wired directly into the production inbound certificate processing path (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can send crafted `PerasCert` messages to inflate the chain weight of any block by an unbounded amount, causing honest nodes to prefer a non-canonical chain or to treat volatile blocks as immutable — a direct analog to the GasAccounting `reconcile()` bug where `maxApprovedGasSpend` was added to `deposits` without being backed by actual funds.

---

### Finding Description

**Root cause — `validatePerasCert` is a stub that always returns `Right`:** [1](#0-0) 

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

No cryptographic proof, no committee membership check, no round-range check, no block-age check (`perasBlockMinSlots`), and no equivocation check is performed. Every certificate from every peer is accepted.

**Production inbound path uses this stub:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` — the stub — as the sole validation gate for all inbound certificates received from peers. The `processCerts` function calls it and, because it always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Accepted certificates are stored and immediately contribute to chain weight:**

`implAddCert` stores every accepted certificate in `pcdsCertsByTicket`, keyed by a monotonically increasing ticket number, with deduplication only by `PerasRoundNo`. [4](#0-3) 

`implGetWeightSnapshot` then builds the `PerasWeightSnapshot` from all stored certificates: [5](#0-4) 

`addToPerasWeightSnapshot` accumulates weights for the same block point using `Map.insertWith (<>)`, so multiple certificates boosting the same block compound their weights: [6](#0-5) 

**Chain selection uses the inflated weight:**

`totalWeightOfFragment` adds `weightBoostOfFragment` (drawn from the snapshot) to the block count, and `preferCandidate` in `WeightedSelectView` compares `wsvTotalWeight` values: [7](#0-6) [8](#0-7) 

**`takeVolatileSuffix` uses total weight to determine the immutable boundary:** [9](#0-8) 

Inflated weight causes blocks to be treated as buried under weight `k` when they are not, preventing legitimate rollbacks.

**The `PerasCertDB` invariant check also notes missing validation:** [10](#0-9) 

---

### Impact Explanation

**Classification: Critical — Bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer can:

1. **Inflate chain weight without bound**: Send N crafted `PerasCert` messages with distinct `PerasRoundNo` values (0, 1, …, N−1), all with `pcCertBoostedBlock` pointing to a block on a fork chain. Each is accepted and stored. `addToPerasWeightSnapshot` accumulates `perasWeight` (default 15) per certificate per block point, yielding a total boost of `15 × N` for that block.

2. **Force chain selection to prefer a non-canonical chain**: Once the fork's total weight (`fork_length + 15 × N`) exceeds the honest chain's total weight (`honest_length`), `preferCandidate` returns `ShouldSwitch`, causing the node to adopt the attacker's chain.

3. **Freeze the immutable boundary at an attacker-chosen block**: `takeVolatileSuffix` returns the longest suffix with total weight ≤ `k`. With enough injected boost, a block deep in the volatile region appears to have weight ≥ `k`, causing the node to treat it as immutable and refuse to roll back past it — permanently locking in the attacker's fork.

---

### Likelihood Explanation

**High** when Peras is enabled. The object diffusion mini-protocol (`makePerasCertPoolWriterFromChainDB`) is the standard peer-to-peer certificate exchange path. Any connected peer — no special privileges, no key material — can send `PerasCert` messages. The only deduplication is by `PerasRoundNo`; an attacker simply uses a fresh round number for each certificate. The CHANGELOG confirms that chain selection is already weight-based when Peras is enabled. [11](#0-10) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the certificate carries a valid aggregate BLS signature from a quorum of committee members for the claimed round.
2. Checks that `pcCertBoostedBlock` refers to a block at least `perasBlockMinSlots` old relative to the round start.
3. Checks that `pcCertRound` is within the valid window (not expired per `perasCertMaxRounds`).
4. Rejects equivocating certificates (same round, different `pcCertBoostedBlock`) — the test model already encodes this invariant but the production `implAddCert` does not enforce it.

Until real validation is in place, the inbound certificate path should be disabled or gated behind a feature flag that is off by default, consistent with the existing Peras-disabled default.

---

### Proof of Concept

With Peras enabled on a private testnet:

```
# Attacker node connects to honest node via object diffusion.
# Attacker sends N PerasCert messages:
for round in 0..N-1:
    send PerasCert { pcCertRound = round, pcCertBoostedBlock = fork_tip }

# Each cert passes validatePerasCert (always Right).
# PerasWeightSnapshot for fork_tip accumulates: 15 * N.
# totalWeightOfFragment(fork) = fork_length + 15 * N.
# If 15 * N > honest_length - fork_length:
#   preferCandidate returns ShouldSwitch → honest node adopts attacker's fork.
```

The attacker-controlled entry path is: peer connection → object diffusion mini-protocol → `processCerts` → `validatePerasCert mkPerasParams` (stub, always `Right`) → `ChainDB.addPerasCertAsync` → `PerasCertDB` → `PerasWeightSnapshot` → `totalWeightOfFragment` → `preferCandidate`. [12](#0-11) [13](#0-12) [14](#0-13) [6](#0-5) [15](#0-14)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L319-328)
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

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```
