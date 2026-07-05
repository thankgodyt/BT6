### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Arbitrary Chain-Selection Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Because the production ObjectDiffusion ingest path (`makePerasCertPoolWriterFromChainDB`) calls this stub directly, any unprivileged peer can inject a `PerasCert` with an arbitrary `pcCertBoostedBlock` field, have it accepted as "validated", and cause the node to apply a Peras weight boost to any block of the attacker's choosing during chain selection.

---

### Finding Description

**Root cause — the stub:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` lines 318–358, the only `BlockSupportsPeras` instance is a universal catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

`validatePerasCert` never inspects the certificate's aggregate BLS signature (`pcSignature`), the voters' eligibility proofs, the round number's relationship to the current slot, or any other semantic constraint. It wraps the raw peer-supplied `cert` directly into a `ValidatedPerasCert` and assigns it the full configured `perasWeight`.

**Production ingest path:**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` lines 113–137, `makePerasCertPoolWriterFromChainDB`, is the production writer used when Peras certificate diffusion is active:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
```

`processCerts` (lines 156–185) calls `validateCert` on each inbound certificate; because `validatePerasCert` always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`.

**Chain-selection side-effect:**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs` lines 483–532, `chainSelSync` for `ChainSelAddPerasCert`, reads `getPerasCertBoostedBlock cert` and calls `chainSelectionForBlock` for that block. The `WeightedSelectView` comparator (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs` lines 58–87) adds `vpcCertBoost` to the block's total weight, so a boosted fork can now outweigh the honest chain.

**Attacker-controlled field:**

The `PerasCert` data type (lines 323–328) carries `pcCertBoostedBlock :: Point blk`, which is fully attacker-controlled. There is no check that the claimed boosted block was actually voted on by a quorum of eligible committee members.

---

### Impact Explanation

An unprivileged peer that has established an ObjectDiffusion connection can send a `PerasCert` naming any block in the receiving node's VolatileDB as `pcCertBoostedBlock`. The node will:

1. Accept the certificate without signature or eligibility verification.
2. Store it in the `PerasCertDB` and update the `PerasWeightSnapshot`.
3. Trigger `chainSelectionForBlock` for the attacker-chosen block.
4. Potentially switch to a fork containing that block if its total weight (block number + injected Peras boost) exceeds the current selection's total weight.

This is a **High/Critical chain-selection manipulation**: an unprivileged peer can make an honest node prefer a non-canonical or adversarially-chosen chain beyond the intended security assumptions of Ouroboros Praos/Peras, violating the Common Prefix property.

---

### Likelihood Explanation

- **Attacker preconditions**: Only a standard peer connection is required; no keys, stake, or privileged access are needed.
- **Trigger**: Sending a single well-formed CBOR-encoded `PerasCert` message over the ObjectDiffusion mini-protocol.
- **Constraint**: The boosted block must already be present in the target node's VolatileDB (i.e., within the volatile window), and the injected boost must be large enough to overcome the honest chain's block-number advantage. Both conditions are realistic in a targeted attack against a node that has received a competing fork.
- **Deployment status**: The ObjectDiffusion certificate ingest path and `chainSelSync` handler are present in production code; the `validatePerasCert` stub is explicitly marked TODO with a known issue reference (`cardano-peras/issues/120`), confirming the gap is known but not yet closed.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` using the public keys of the claimed voters.
2. Checks each voter's eligibility proof (VRF output for non-persistent members, committee membership for persistent members) against the current stake distribution and committee selection.
3. Verifies that the number of eligible voters and their combined stake meet the quorum threshold (`perasQuorumStakeThreshold`).
4. Validates that `pcCertRound` is within the acceptable window relative to the current slot.

Until a real implementation is available, the production `makePerasCertPoolWriterFromChainDB` should refuse all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all, so that the stub's permissiveness does not reach the chain-selection path.

---

### Proof of Concept

**Setup**: Node A is running with Peras ObjectDiffusion enabled. Node A has block `B_fork` (a competing fork tip) in its VolatileDB.

**Attacker steps**:

1. Connect to Node A as a peer via the ObjectDiffusion mini-protocol.
2. Craft a `PerasCert` value:
   ```
   PerasCert
     { pcCertRound    = <any round number not yet in Node A's PerasCertDB>
     , pcCertBoostedBlock = BlockPoint <slot of B_fork> <hash of B_fork>
     }
   ```
3. Send this certificate to Node A in an `ObjectDiffusion` message batch.

**Expected outcome (current code)**:

- `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
- The certificate is added to `PerasCertDB`; `PerasWeightSnapshot` is updated to assign `perasWeight` to `B_fork`.
- `chainSelSync` triggers `chainSelectionForBlock` for `B_fork`.
- `WeightedSelectView` now computes `totalWeight(fork containing B_fork) = blockNo(B_fork) + perasWeight`, which may exceed `totalWeight(honest chain) = blockNo(honest tip)`.
- Node A switches to the attacker-chosen fork.

**Root cause confirmed**: `validatePerasCert` at lines 353–358 of `SupportsPeras.hs` returns `Right` unconditionally, and `makePerasCertPoolWriterFromChainDB` at lines 118–137 of `PerasCert.hs` passes this stub directly into the live chain-selection path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-544)
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
 where
  tracer :: Tracer m (TraceAddPerasCertEvent blk)
  tracer = TraceAddPerasCertEvent >$< cdbTracer

  certRound :: PerasRoundNo
  certRound = getPerasCertRound cert

  boostedBlock :: Point blk
  boostedBlock = getPerasCertBoostedBlock cert
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
