### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Inflating `PerasWeightSnapshot` and Corrupting Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is a no-op stub that unconditionally returns `Right` for every inbound certificate. Because the ObjectDiffusion mini-protocol feeds peer-supplied `PerasCert` objects through this stub before storing them in `PerasCertDB`, any unprivileged peer can inject an arbitrary certificate for any round number and any block point. The stored certificate immediately inflates the `PerasWeightSnapshot` used by chain selection, causing an honest node to prefer a non-canonical, adversarially-boosted chain. The same injected certificate also corrupts `pcdsLatestCertSeen`, which drives the Peras voting rules (VR-1A through VR-2B).

---

### Finding Description

**Root cause — stub validator that always succeeds**

The `BlockSupportsPeras` default instance in `SupportsPeras.hs` carries an explicit TODO and performs zero cryptographic or semantic checks:

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

This instance is the one wired into both production pool writers:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

**Inbound path — `processCerts`**

`processCerts` calls `validateCert` on every peer-supplied certificate. Because the validator always returns `Right`, every certificate passes and is timestamped and forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Storage — `implAddCert` also carries a missing-validation TODO**

`implAddCert` itself is marked with the same unresolved issue:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
``` [4](#0-3) 

On every new certificate, `implAddCert` unconditionally updates `pcdsLatestCertSeen` to whichever certificate has the highest round number seen so far:

```haskell
pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
  Nothing -> Just cert
  Just prev
    | getPerasCertRound cert > getPerasCertRound prev -> Just cert
    | otherwise -> Just prev
``` [5](#0-4) 

**Chain selection — `PerasWeightSnapshot` inflated by fake certificates**

`getWeightSnapshot` builds the snapshot directly from every certificate in `pcdsCertsByTicket`:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [6](#0-5) 

`mkPerasWeightSnapshot` accumulates boosts additively (`Map.insertWith (<>)`), so multiple fake certificates for different rounds targeting the same block compound the boost. [7](#0-6) 

This snapshot is passed directly into `ChainSelEnv` and used by `weightedSelectView` / `preferCandidate` to decide whether to switch chains:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
    ...
``` [8](#0-7) 

The chain selection event triggered by a new certificate (`ChainSelAddPerasCert`) re-runs selection for the boosted block using this inflated snapshot: [9](#0-8) 

**Voting rules — `latestCertSeen` corrupted**

`getLatestCertSeen` returns `pcdsLatestCertSeen` directly. The Peras voting rules (VR-1A, VR-1B, VR-2A, VR-2B) all branch on this value. An attacker who injects a certificate with a far-future round number causes `latestCertSeen` to point to that round, making VR-1A (`currRoundNo == certRound + 1`) permanently false and silencing the node's votes for all subsequent rounds. [10](#0-9) 

---

### Impact Explanation

**Chain selection safety failure (High).** An unprivileged peer can inject one or more fake `PerasCert` objects targeting blocks on a minority or adversarial chain. Each accepted certificate adds `perasWeight` boost to those blocks in the `PerasWeightSnapshot`. Once the cumulative boost exceeds the honest chain's length advantage, `preferCandidate` returns `ShouldSwitch` and the node adopts the adversarial chain. Because the boost is additive and unbounded (one certificate per round, and there is no round-number bound enforced at ingest), the attacker can accumulate arbitrarily large weight for any target block.

**Voting rule bypass (High).** By injecting a certificate with a round number far ahead of the current round, the attacker sets `latestCertSeen` to a future round. VR-1A requires `currRoundNo == certRound + 1`; with a far-future `certRound` this is never satisfied, permanently suppressing the victim node's votes. This weakens the quorum-reaching ability of the honest committee.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is a standard node-to-node interface reachable by any peer. Constructing a `PerasCert blk` requires only a `PerasRoundNo` and a `Point blk` — both are plain data with no cryptographic material required. The stub validator imposes no barrier. A single malicious peer connected to the victim node can execute this attack immediately.

---

### Recommendation

1. **Replace the stub `validatePerasCert`** with a real implementation that verifies the aggregate BLS/KES signature over the certificate, checks that the claimed voters are eligible committee members for the stated round (using the epoch's stake distribution), and confirms the quorum threshold is met. This is tracked in issue #120.

2. **Add a round-number bound check at ingest** in `processCerts` / `implAddCert`: reject any certificate whose round number is more than a small constant ahead of the current round, preventing far-future `latestCertSeen` injection.

3. **Add a per-round deduplication check** in `implAddCert` that rejects a certificate for a round already present in `pcdsCertIds` even if it targets a different block (equivocation rejection), preventing weight accumulation via round collisions.

---

### Proof of Concept

```
Attacker node A connects to honest node H via the ObjectDiffusion mini-protocol.

1. A observes that H's current chain tip is at block B_honest (BlockNo 100).
2. A has a minority chain with tip B_adv (BlockNo 95, 5 blocks shorter).
3. A crafts 6 PerasCert values:
     cert_i = PerasCert { pcCertRound = i, pcCertBoostedBlock = Point(B_adv) }
   for i in [1..6].
   No cryptographic material is needed; the stub validator accepts all of them.
4. A sends these 6 certs to H via ObjectDiffusion.
5. processCerts calls validatePerasCert mkPerasParams on each cert.
   validatePerasCert always returns Right, so all 6 pass.
6. Each cert is stored in PerasCertDB. mkPerasWeightSnapshot accumulates:
     weight(B_adv) = 6 * perasWeight   (e.g., 6 * 1 = 6 if perasWeight = 1)
7. chainSelSync fires for B_adv. weightedSelectView computes:
     wsvTotalWeight(H's chain) = BlockNo(100) + 0 = 100
     wsvTotalWeight(A's chain) = BlockNo(95)  + 6 = 101
8. preferCandidate returns ShouldSwitch(Heavier ...).
9. H switches to A's shorter, adversarial chain.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L184-188)
```haskell
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L75-82)
```haskell
mkPerasWeightSnapshot ::
  StandardHash blk =>
  [(Point blk, PerasWeight)] ->
  PerasWeightSnapshot blk
mkPerasWeightSnapshot =
  Foldable.foldl'
    (\s (pt, weight) -> addToPerasWeightSnapshot pt weight s)
    emptyPerasWeightSnapshot
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L129-165)
```haskell
perasVR1A ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR1A
  PerasVotingView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    VR1A := vr1a1 :/\: vr1a2
   where
    -- The latest certificate seen is from the previous round
    vr1a1 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0

    -- The latest certificate seen was received within X slots from the start
    -- of its round
    vr1a2 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its arrival time
        NotOrigin cert ->
          lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True

    _X =
      SlotNo $
        unPerasCertArrivalThreshold $
          perasCertArrivalThreshold perasParams
```
