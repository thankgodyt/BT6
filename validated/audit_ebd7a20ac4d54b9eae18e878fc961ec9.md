### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Inbound Certificate, Enabling Unauthorized Chain Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that always returns `Right` (success) without performing any cryptographic verification. When Peras is enabled via feature flags, an unprivileged peer can send a crafted `PerasCert` for any round, have it unconditionally accepted, and cause the receiving node to assign extra chain weight to an arbitrary block in its VolatileDB — potentially making a non-canonical chain appear heavier and triggering a chain switch.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must verify a certificate's cryptographic integrity before it influences chain selection. The only instance currently in the codebase is a catch-all stub:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

Every certificate, regardless of its cryptographic content, is wrapped in `ValidatedPerasCert` and returned as `Right`. No signature, quorum, or committee membership check is performed.

This stub is the `validateCert` argument wired into both inbound certificate pool writers:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass, adds them to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate clears this gate. Once in the `PerasCertDB`, the certificate's boosted block point is included in the `PerasWeightSnapshot` returned by `getWeightSnapshot`: [4](#0-3) 

Chain selection then calls `chainSelectionForBlock` for the boosted block, and `preferAnchoredCandidate` uses the real (now attacker-inflated) `PerasWeightSnapshot` to compare fragments: [5](#0-4) [6](#0-5) 

**Analog to TapiocaOFT H-58:** In TapiocaOFT, `_wrap` checked the TapiocaOFT allowance (the wrong state) instead of the underlying ERC20 allowance (the correct state), so the authorization check was present but verified nothing meaningful. Here, `validatePerasCert` is called (the check is present) but the implementation verifies nothing (the wrong/empty state), so any certificate passes. In both cases the authorization gate exists in the call graph but is bypassed because it checks the wrong object.

---

### Impact Explanation

When Peras is enabled via `rnFeatureFlags`, an unprivileged peer connected via the object-diffusion mini-protocol can:

1. Observe a block hash `H` present in the target node's VolatileDB (visible through normal ChainSync).
2. Craft a `PerasCert` for any round number, claiming to boost block `H`.
3. Send the certificate; `validatePerasCert` returns `Right` unconditionally.
4. The certificate enters the `PerasCertDB`; block `H` gains `perasWeight` extra weight.
5. `chainSelectionForBlock` is triggered; if the chain containing `H` now has higher total weight than the current selection, the node switches to it.

A chain that is otherwise shorter or weaker than the canonical chain can be made to appear heavier by a single forged certificate, causing the honest node to adopt a non-canonical chain. This is a **High** chain-selection integrity failure: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

- **Peras must be enabled**: it is off by default but is reachable via `rnFeatureFlags` in `RunNodeArgs`, including on private testnets.
- **No privileged access required**: any connected peer can send `PerasCert` objects through the object-diffusion protocol.
- **Attacker knowledge required**: the attacker must know a block hash present in the target's VolatileDB, which is observable through normal ChainSync.
- **One certificate per round**: the `PerasCertDB` deduplicates by round number, but an attacker can send one forged certificate per Peras round, each boosting a different block.

Likelihood is **Medium** (conditional on Peras being enabled; trivially exploitable once it is).

---

### Recommendation

Replace the stub with a real implementation that calls the voting committee's `verifyCert` method (already defined in `Ouroboros.Consensus.Committee.Class`) against the epoch-appropriate `InterEpochVotingCommittee` before constructing a `ValidatedPerasCert`. The `PerasCertCompatibleWithVotingCommittee` conversion layer and `implVerifyCert` in `WFALS.hs` already provide the cryptographic machinery; `validatePerasCert` must invoke it. [7](#0-6) 

Until proper validation is wired in, `validatePerasCert` must not be used in any code path reachable from an untrusted peer when Peras is enabled.

---

### Proof of Concept

**Setup**: private testnet with Peras enabled, attacker is a connected peer.

1. Attacker observes via ChainSync that the target node's VolatileDB contains block `B` at point `(slot=S, hash=H)` on a fork that is currently not selected (e.g., one block shorter than the canonical chain, so its `BlockNo` is equal to the canonical tip's `BlockNo - 1`).

2. Attacker constructs:
   ```
   PerasCert { pcCertRound = <any unused round R>, pcCertBoostedBlock = BlockPoint S H }
   ```

3. Attacker sends this certificate via the object-diffusion mini-protocol.

4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.

5. Certificate is added to `PerasCertDB`; `getWeightSnapshot` now returns a snapshot where point `(S, H)` has weight `perasWeight params`.

6. `chainSelectionForBlock` is triggered for block `B`. `preferAnchoredCandidate` computes:
   - Our chain total weight = `BlockNo_canonical + 0` (no boosts)
   - Fork total weight = `(BlockNo_canonical - 1) + perasWeight` 
   - If `perasWeight ≥ 1`, the fork is now heavier; `ShouldSwitch` is returned.

7. The node rolls back to the fork, adopting the non-canonical chain. [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-494)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
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
