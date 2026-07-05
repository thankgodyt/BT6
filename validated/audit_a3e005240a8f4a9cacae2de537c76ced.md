### Title
Stub `validatePerasCert` Unconditionally Accepts Any Certificate, Enabling Arbitrary Peras Weight Injection and Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or protocol validation. An unprivileged peer can send crafted `PerasCert` objects via the certificate diffusion miniprotocol; each passes "validation," is stored in `PerasCertDB`, and its boost is accumulated into the `PerasWeightSnapshot`. Because chain selection (`preferAnchoredCandidate`) uses that snapshot to compare chain weights, the attacker can inflate the weight of any block they choose, causing honest nodes to prefer an adversarial chain over the canonical chain.

---

### Finding Description

**Root cause — stub validation always succeeds:** [1](#0-0) 

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

Every `PerasCert` — regardless of its round number, boosted-block point, or aggregate signature — is accepted and wrapped in a `ValidatedPerasCert` carrying the configured `perasWeight` boost. No signature is checked, no quorum is verified, no round-validity rule is applied.

**Inbound path — `processCerts` calls the stub:** [2](#0-1) 

`processCerts` receives a batch of `PerasCert` objects from a peer, filters out round numbers already in the DB, calls `validateCert` (bound to `validatePerasCert`) on the remainder, and — if all pass — stores them. Because the stub never returns `Left`, every novel-round certificate is stored unconditionally.

**Weight accumulation — `addToPerasWeightSnapshot` uses `Sum Word64`:** [3](#0-2) 

```haskell
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```

`PerasWeight` is `newtype … Word64` with `deriving via Sum Word64 instance Semigroup PerasWeight`, so `<>` is modular `Word64` addition. [4](#0-3) 

Multiple certificates boosting the same block point accumulate their weights. An attacker who sends N certificates (each for a distinct round, all naming the same `pcCertBoostedBlock`) causes that block's entry in the snapshot to grow by `N × perasWeight`. Because `Word64` arithmetic wraps, a sufficiently large N causes the stored weight to overflow and wrap to a small value — the exact "extreme-value bomb" pattern from the reference report.

**Chain selection consumes the snapshot:** [5](#0-4) 

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare = mconcat [ compare `on` wsvTotalWeight, compare `on` wsvTiebreaker ]
```

`preferCandidate` compares `wsvTotalWeight` values: [6](#0-5) 

A manipulated (inflated or overflowed) weight directly controls which chain is selected.

**Volatile-suffix computation is also affected:** [7](#0-6) 

`takeVolatileSuffix` uses `totalWeightOfFragment snap ≤ k` to decide which blocks are immutable. If the weight of a boosted block overflows and wraps to a small value, the suffix considered "volatile" (rollback-eligible) grows beyond the intended security parameter `k`.

---

### Impact Explanation

**Phase 1 — immediate chain-selection manipulation (no overflow needed):** An attacker sends crafted certificates boosting a block on an adversarial fork. Because `validatePerasCert` always succeeds, those certificates are stored and their boosts appear in the weight snapshot. `preferAnchoredCandidate` then sees the adversarial fork as heavier and switches to it. This is a **critical chain-selection safety failure** triggered by a single unprivileged peer connection.

**Phase 2 — overflow bomb (analogous to the reference report's share-inflation):** If the attacker sends enough certificates all naming the same block point, the accumulated `PerasWeight` (a `Word64`) wraps around to a small value. `wsvTotalWeight` for a chain containing that block then appears lighter than it truly is. `takeVolatileSuffix` consequently treats blocks buried under more than `k` weight as still volatile, breaking the rollback-depth guarantee and allowing the attacker to force a rollback beyond `k` — a permanent consensus-safety violation.

---

### Likelihood Explanation

The entry path requires only a peer connection and the ability to send `PerasCert` messages. No stake, no keys, no privileged access. The deduplication in `implAddCert` (one cert per `PerasRoundNo`) limits the rate of injection per round number, but `PerasRoundNo` is a `Word64` with `2^64` possible values, so the attacker has an effectively unbounded supply of distinct round numbers to use. Phase 1 impact is achievable with a single crafted certificate; Phase 2 requires a large but finite number of messages.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate BLS signature over the election ID and candidate block, confirm the quorum threshold is met by the attesting voters' stake, and check that the round number and boosted-block point satisfy all protocol rules. Remove the stub and the associated TODO.

2. **Cap or bound `PerasWeight` accumulation per block point** in `addToPerasWeightSnapshot` (e.g., clamp at `maxBound` or reject a second boost for the same point in the same epoch) to prevent `Word64` wrap-around from silently corrupting the weight snapshot.

3. **Add a minimum-balance / minimum-weight reserve** analogous to the reference report's recommendation: ensure the weight snapshot cannot be driven to a state where `wsvTotalWeight` wraps around by enforcing an upper bound on the total boost any single block point can accumulate.

---

### Proof of Concept

```
1. Attacker opens a peer connection to an honest Cardano node running this codebase.

2. Attacker constructs a PerasCert:
     pcCertRound       = PerasRoundNo 999999   -- any unused round
     pcCertBoostedBlock = <point of attacker's adversarial fork tip>

3. Attacker sends the cert via the Peras certificate diffusion miniprotocol.

4. processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right (ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams })

5. implAddCert stores the cert; implGetWeightSnapshot now returns a snapshot
   where the adversarial fork tip carries weight perasWeight (= 15 by default).

6. preferAnchoredCandidate calls weightedSelectView on both the honest chain
   and the adversarial fork. The adversarial fork's wsvTotalWeight is now
   blockNo + 15, while the honest chain's is blockNo + 0.
   → ShouldSwitch is returned; the node adopts the adversarial fork.

Phase-2 (overflow): repeat step 2–5 with distinct PerasRoundNo values,
all naming the same pcCertBoostedBlock. After ⌈2^64 / 15⌉ ≈ 1.2×10^18
injections the accumulated Word64 wraps to 0, making takeVolatileSuffix
treat all blocks as volatile and breaking the k-rollback guarantee.
``` [1](#0-0) [8](#0-7) [3](#0-2) [4](#0-3) [6](#0-5) [7](#0-6) [9](#0-8)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L84-91)
```haskell
newtype PerasWeight
  = PerasWeight {unPerasWeight :: Word64}
  deriving Show via Quiet PerasWeight
  deriving stock Generic
  deriving newtype (Enum, Eq, Ord, NoThunks, Condense)

deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
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
