### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection Weight — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance used in production unconditionally accepts every inbound Peras certificate as valid, performing zero cryptographic or semantic checks. An unprivileged peer can send a crafted `PerasCert` via the certificate diffusion mini-protocol to artificially boost any block in the VolatileDB, causing the node to prefer a non-canonical chain. This is a direct analog to the external report's pattern: a validation gate that always passes, enabling unauthorized manipulation of shared state (chain selection weight instead of pool membership).

---

### Finding Description

**Root cause — stub `validatePerasCert` always returns `Right`:**

The `BlockSupportsPeras` instance is explicitly labelled a "degenerate instance for all blks to get things to compile": [1](#0-0) 

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

No signature check, no committee membership check, no round/block validity check — every certificate is accepted and assigned the full `perasWeight`.

**Production wiring — this stub is the validator used for inbound peer certificates:**

`makePerasCertPoolWriterFromChainDB` in `ObjectPool/PerasCert.hs` passes `validatePerasCert mkPerasParams` directly as the validation function for all certificates received from peers: [2](#0-1) 

`processCerts` calls this validator on each inbound certificate; if all pass (they always do), each is timestamped and added to the `PerasCertDB` via `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection consequence — the fake certificate triggers a fork switch:**

`chainSelSync` processes the certificate by looking up the `pcCertBoostedBlock` in the VolatileDB and calling `chainSelectionForBlock` for it: [4](#0-3) 

Chain selection then computes the weight of candidate fragments using `weightBoostOfFragment`, which sums `weightBoostOfPoint` for every block on the fragment using the `PerasWeightSnapshot` derived from the `PerasCertDB`: [5](#0-4) 

The `WeightedSelectView` comparison then prefers the candidate with higher total weight (block count + boost): [6](#0-5) 

**End-to-end exploit path:**

1. Attacker connects as a peer to a node with Peras enabled.
2. Attacker sends a crafted `PerasCert` with `pcCertBoostedBlock` pointing to a block on a competing fork that is currently lighter than the honest chain.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → unconditionally returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
4. Certificate is inserted into `PerasCertDB`; `addPerasCertAsync` enqueues a chain selection event.
5. `chainSelSync` retrieves the boosted block from the VolatileDB, recomputes fragment weights including the new boost, and switches to the attacker's fork if its total weight now exceeds the current chain.

---

### Impact Explanation

**High — chain selection manipulation.** An unprivileged peer can cause an honest node to abandon the canonical chain and adopt a non-canonical fork by sending a single crafted certificate. This bypasses the entire Peras security model (quorum of committee members, BLS aggregate signature verification) and directly violates the chain selection invariant. The impact matches: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

Peras is disabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference` — CHANGELOG). However, the production diffusion infrastructure is fully wired up and the vulnerability is present in production files, not test files. Any operator enabling Peras (e.g., on a private testnet or future mainnet activation) is immediately exposed. The attack requires only a peer connection and the ability to send a single well-formed CBOR-encoded `PerasCert` message — no keys, no stake, no prior state.

---

### Recommendation

1. Implement real cryptographic and semantic validation in `validatePerasCert` before Peras is enabled in any environment. At minimum: verify the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)`, verify committee membership and quorum stake threshold, and verify the round number is within the valid window.
2. Remove or gate the degenerate `instance StandardHash blk => BlockSupportsPeras blk` so it cannot be used in production code paths. The TODO at line 318 references [tweag/cardano-peras#73](https://github.com/tweag/cardano-peras/issues/73) and [tweag/cardano-peras#120](https://github.com/tweag/cardano-peras/issues/120).
3. Add a compile-time or runtime guard that prevents `makePerasCertPoolWriterFromChainDB` from being instantiated with the stub validator.

---

### Proof of Concept

```
# On a private testnet with Peras enabled:

1. Attacker node connects to honest node via the Peras cert diffusion mini-protocol.

2. Attacker constructs a PerasCert (CBOR, 2-field list):
     pcCertRound      = <any valid round number>
     pcCertBoostedBlock = <Point of a block on a competing fork in the honest node's VolatileDB>

3. Attacker sends the cert via ObjectDiffusion.
   processCerts calls validatePerasCert mkPerasParams cert
   → returns Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }
   → cert is added to PerasCertDB, addPerasCertAsync is called.

4. chainSelSync processes the cert:
   - Looks up pcCertBoostedBlock in VolatileDB → found (block on competing fork).
   - Calls chainSelectionForBlock for that block.
   - weightBoostOfFragment now includes the fake boost for the competing fork.
   - WeightedSelectView comparison: competing fork total weight > honest chain total weight.
   - Node switches to the competing fork.

5. Honest node is now on the attacker-chosen non-canonical chain.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-268)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
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
