### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Because this function is the live gate used by `processCerts` when handling inbound Peras certificates from network peers, any unprivileged peer can inject arbitrary `PerasCert` values that are accepted without question, stored in `PerasCertDB`, and then used to inflate the Peras weight of attacker-chosen blocks in chain selection. This is the direct consensus analog of the external report's "authority sets nominals without validation" pattern: the authority here is any network peer, the unchecked values are the boosted-block points in the certificate, and the exploited mechanism is the `PerasWeightSnapshot`-driven chain comparison.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`** [1](#0-0) 

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

No signature check, no committee-membership check, no round-number bounds check, no boosted-block existence check — the function accepts every certificate unconditionally and stamps it with the full configured `perasWeight`.

**Inbound path — `processCerts` calls this gate for every peer-supplied certificate** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` (the production writer) passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Storage — `implAddCert` stores the certificate with no further checks** [4](#0-3) 

The only guard is a duplicate-round-number check (`Set.member roundNo`). No validation of the boosted block's existence, era, or relationship to the current chain is performed.

**Weight snapshot — stored certificates directly feed chain selection** [5](#0-4) 

`implGetWeightSnapshot` builds a `PerasWeightSnapshot` from every stored certificate's `(boostedBlock, boost)` pair. This snapshot is read atomically during every chain-selection event.

**Chain selection — the snapshot determines which chain wins** [6](#0-5) 

`wsvTotalWeight` adds `wsvBlockNo` and `wsvWeightBoost`; `preferCandidate` switches to a candidate chain whenever its total weight exceeds the current chain's. An attacker-injected certificate that boosts a block on the attacker's fork directly increases that fork's total weight. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block point as the boosted block and any round number not yet in the database. Because `validatePerasCert` never rejects anything, the certificate is stored and its `perasWeight` boost is applied to that block in every subsequent chain-selection comparison. With a sufficiently large `perasWeight` (the configured value, currently a protocol parameter), a single injected certificate can make the attacker's fork appear heavier than the honest chain, causing the victim node to switch to the attacker's fork. This satisfies the **High** impact criterion: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The analog to the external report is exact: the `authority` that sets unchecked values is any network peer; the unchecked "nominals" are the `pcCertBoostedBlock` and `vpcCertBoost` fields; the "rebalancer profiting" is the attacker's fork being selected over the honest chain.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol (`ObjectDiffusion`) is an externally reachable network endpoint. Any peer that can connect to the node can send `PerasCert` objects. The only deduplication guard is a round-number set membership check, which an attacker trivially bypasses by using a fresh round number. No stake, key material, or privileged access is required. The attack is therefore reachable by any unprivileged peer with a network connection.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion path is enabled in production. At minimum, validation must verify:

1. **Committee membership and cryptographic signature** — the certificate must be signed by a quorum of eligible committee members for the claimed round.
2. **Boosted block existence and era** — `pcCertBoostedBlock` must refer to a block that actually exists on a known chain and is within the valid age window (`perasCertMaxRounds`).
3. **Round-number plausibility** — the round number must be within the current or recent past, not arbitrarily far in the future.

Until real validation is in place, the inbound certificate processing path should be disabled or gated behind a feature flag that is off by default.

---

### Proof of Concept

1. Attacker connects to a victim node via the Peras certificate ObjectDiffusion mini-protocol.
2. Attacker sends a `PerasCert { pcCertRound = <fresh round>, pcCertBoostedBlock = <tip of attacker's fork> }`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
4. `implAddCert` stores the certificate (round number is new, so the duplicate guard passes).
5. Next chain-selection event reads `implGetWeightSnapshot`, which now includes `(attackerForkTip, perasWeight)`.
6. `preferAnchoredCandidate` computes `wsvTotalWeight` for the attacker's fragment: `blockNo + perasWeight`. If `perasWeight` is large enough (e.g., the default of 15 blocks), the attacker's fork wins even if it is shorter than the honest chain by up to 14 blocks.
7. The victim node switches to the attacker's fork. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

```
