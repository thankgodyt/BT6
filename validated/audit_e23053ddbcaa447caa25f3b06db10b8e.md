### Title
Unconditional `validatePerasCert` Acceptance Enables Adversarial Peras Certificate Injection and Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic, structural, or committee-membership validation on inbound Peras certificates. An unprivileged peer can send a crafted certificate boosting any block hash, which is accepted without question, stored in the `PerasCertDB`, and immediately fed into chain selection — inflating the `wsvTotalWeight` of an adversarial chain fragment and potentially causing the node to switch away from the honest chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must approve every inbound certificate before it enters the node's state: [1](#0-0) 

The only concrete instance in the codebase is a universal stub:

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
``` [2](#0-1) 

This instance covers **all** block types (`instance StandardHash blk => BlockSupportsPeras blk`), including production Cardano blocks. No signature, quorum, committee-membership, round-validity, or boosted-block-existence check is performed.

The production inbound path is `makePerasCertPoolWriterFromChainDB`, wired into the node-to-node diffusion layer: [3](#0-2) 

Its `opwAddObjects` handler calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function: [4](#0-3) 

`processCerts` partitions results with `partitionEithers (validateCert <$> certsNotAlreadyInDb)`. Since `validatePerasCert` always returns `Right`, the error branch is never taken and every certificate is unconditionally forwarded to `addCert`: [5](#0-4) 

The accepted certificate is then stored and triggers `chainSelSync` → `ChainSelAddPerasCert`, which calls `chainSelectionForBlock` for the boosted block: [6](#0-5) 

Chain selection computes `wsvTotalWeight = blockNo + weightBoost`, where `weightBoost` is drawn from the `PerasWeightSnapshot` populated by the fake certificate: [7](#0-6) 

A fragment whose boosted block carries an injected `perasWeight` will appear heavier than the honest chain and be selected: [8](#0-7) 

---

### Impact Explanation

An adversarial peer can inject a `PerasCert` naming any block hash as `pcCertBoostedBlock`. The node accepts it, adds the configured `perasWeight` boost to that block's entry in the `PerasWeightSnapshot`, and re-runs chain selection. If the boosted block is on a fork the adversary is serving, the node will switch to that fork even though it is shorter or otherwise non-canonical. This is a **bypass of Peras certificate validation** enabling unauthorized certificate acceptance and a **chain selection error** that lets an unprivileged peer make an honest node prefer a non-canonical chain — matching the Critical/High impact tiers in the allowed scope.

---

### Likelihood Explanation

The object diffusion mini-protocol is reachable by any connected peer without authentication. The `PerasCert` wire type is simple (a round number and a block point), trivially constructable. No stake, key material, or special privilege is required. The only existing guard — the `alreadyInDb` deduplication check — only prevents re-injection of a certificate for the same round number, not injection of a certificate for a new round pointing at an adversarial block. Likelihood is **high** whenever Peras is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation covering at minimum:

1. **Committee membership**: the certificate must be signed by a quorum of elected committee members for the claimed round.
2. **Round validity**: `pcCertRound` must correspond to a round that is plausible given the current slot.
3. **Boosted block existence and ancestry**: `pcCertBoostedBlock` must be a block that was actually eligible to be voted on in that round.
4. **Signature/aggregate-signature verification**: the cryptographic proof of quorum must be checked.

Until a real instance is available, the node should refuse to enable Peras certificate diffusion (i.e., not wire up `makePerasCertPoolWriterFromChainDB`) rather than accept all certificates unconditionally. [9](#0-8) 

---

### Proof of Concept

1. Attacker connects to a Peras-enabled node via the node-to-node object diffusion mini-protocol.
2. Attacker constructs a `PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlockPoint }` where `adversarialBlockPoint` is the tip of a fork the attacker is serving via ChainSync.
3. The node's `makePerasCertPoolWriterFromChainDB` receives the certificate batch.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCertBoost = perasWeight defaultParams })` unconditionally.
5. The certificate is stored in `PerasCertDB`; `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` processes the message: the adversarial block is found in the `VolatileDB`, `chainSelectionForBlock` is called.
7. `weightedSelectView` computes `wsvTotalWeight` for the adversarial fragment, which now includes the injected boost.
8. `preferCandidate` returns `ShouldSwitch` because the adversarial fragment's total weight exceeds the honest chain's.
9. The node adopts the adversarial chain. [5](#0-4) [10](#0-9) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
