### Title
`validatePerasCert` Performs No Cryptographic Validation, Allowing Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the only instance in production — implements `validatePerasCert` as an unconditional `Right`, accepting every inbound certificate without any cryptographic or structural check. An unprivileged peer can therefore inject arbitrarily many crafted `PerasCert` messages (one per distinct round number) via the Peras certificate diffusion mini-protocol. Each accepted certificate adds `PerasWeight 15` to the boosted block's chain weight, which is consumed directly by `chainSelSync` to trigger a chain-selection re-evaluation. By flooding a node with certs that all boost a block on a minority fork, an attacker can make the node's weighted chain-selection prefer that fork over the honest majority chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The sole `BlockSupportsPeras` instance (the "degenerate instance for all blks to get things to compile") implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
```

No signature, committee membership, round-number range, or boosted-block validity check is performed. Every `PerasCert` value, regardless of content, is promoted to a `ValidatedPerasCert` carrying the full protocol boost weight. [1](#0-0) 

**Inbound path — peer-submitted certs reach `validatePerasCert` directly:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as the sole validation callback for all peer-submitted certificates:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on each cert not already in the DB; if all pass (they always do), it calls `addCert` for each: [3](#0-2) 

**Deduplication is only by round number — not by content:**

`implAddCert` in `PerasCertDB.Impl` deduplicates solely on `pcCertRound`. An attacker can therefore inject one cert per distinct round number, each boosting the same block: [4](#0-3) 

**Chain selection consumes the injected boost:**

`chainSelSync` processes each accepted cert by calling `chainSelectionForBlock` for the boosted block: [5](#0-4) 

`preferAnchoredCandidate` / `WeightedSelectView.preferCandidate` then compares chains by `wsvTotalWeight = blockNo + weightBoost`. A fork whose tip is N blocks behind the honest chain becomes preferred once it accumulates a boost exceeding N: [6](#0-5) 

**Default boost weight is 15:**

`mkPerasParams` sets `perasWeight = PerasWeight 15`. Injecting certs for rounds 0 through N−1 (all boosting the same block) adds `N × 15` to that block's chain weight: [7](#0-6) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can cause an honest node to permanently switch its selection to a minority or attacker-controlled fork by injecting a batch of crafted `PerasCert` messages (one per round number) that all boost a block on that fork. Because `validatePerasCert` never rejects any certificate, the node's `PerasCertDB` accumulates unbounded artificial weight for the attacker's chosen block. Once the accumulated boost exceeds the honest chain's block-number lead, `preferAnchoredCandidate` returns `ShouldSwitch`, and the node adopts the wrong chain. This is a **High** chain-selection integrity failure: an unprivileged peer makes an honest node prefer a non-canonical chain beyond the intended security assumptions of Ouroboros Peras.

---

### Likelihood Explanation

The attack requires only that Peras is enabled and that the attacker can connect to the target node as a normal peer (no keys, no stake, no privileged access). The Peras certificate diffusion mini-protocol (`ObjectDiffusion`) is reachable from any peer. Constructing a valid-looking `PerasCert` CBOR payload is trivial: it is a 2-element list of a round number and a block point, both of which are attacker-controlled. The attacker can send thousands of such messages in a single connection, one per distinct round number, before the node can react.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before Peras is enabled in production. At minimum, the implementation must:

1. Verify the certificate's cryptographic signature against the committee's public keys for the claimed round.
2. Verify that the signer was a legitimate committee member for that round (committee selection check).
3. Verify that the boosted block point is structurally valid (non-genesis, within the expected slot range for the round).
4. Reject any certificate whose round number is outside the acceptable window relative to the current slot.

Until real validation is implemented, the Peras certificate diffusion path must be disabled or gated behind a feature flag that is off by default in production, so that no peer-submitted cert can reach `addPerasCertAsync`.

---

### Proof of Concept

**Setup:** Node A has Peras enabled. Its current selection is the honest chain at block number 100 (total weight 100). A minority fork exists with a block B at block number 85 (total weight 85), 15 blocks behind.

**Attack:**
1. Attacker connects to Node A as a normal peer.
2. Attacker constructs 2 `PerasCert` CBOR messages:
   - `PerasCert { pcCertRound = 0, pcCertBoostedBlock = point(B) }`
   - `PerasCert { pcCertRound = 1, pcCertBoostedBlock = point(B) }`
3. Attacker sends both certs via the Peras cert diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams` on each → both return `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
5. Both certs are added to `PerasCertDB`; `addPerasCertAsync` is called for each.
6. `chainSelSync` fires for block B twice. The `PerasWeightSnapshot` now records `point(B) → PerasWeight 30`.
7. `preferAnchoredCandidate` computes: honest chain total weight = 100; fork containing B total weight = 85 + 30 = 115.
8. `ShouldSwitch` is returned; Node A switches to the minority fork.

**Expected (correct) behavior:** Both certs are rejected at step 4 with a `PerasValidationErr` because neither carries a valid committee signature. Node A stays on the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
