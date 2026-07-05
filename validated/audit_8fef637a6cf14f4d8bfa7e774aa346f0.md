### Title
Unconditional Peras Certificate Acceptance Bypasses Chain-Selection Weight Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as `pcCertBoostedBlock`, which is accepted without checks, stored in the `PerasCertDB`, and used to trigger chain selection with a weight boost of 15 (`perasWeight mkPerasParams`). This lets an attacker make an honest node prefer a non-canonical fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a stub that always succeeds:**

In the degenerate `BlockSupportsPeras` instance (the only instance that exists), `validatePerasCert` is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
``` [1](#0-0) 

No quorum check, no committee membership check, no cryptographic signature verification, and no check that the boosted block is a valid block on any known chain is performed. The function accepts any `PerasCert` value unconditionally.

**Entry path — inbound certificates from peers flow directly into chain selection:**

`makePerasCertPoolWriterFromChainDB` wires the production object-diffusion writer to use `validatePerasCert mkPerasParams` as its validator:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls this validator on every inbound certificate. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` then processes it: it adds the cert to `PerasCertDB` and, if the boosted block is present in the `VolatileDB`, immediately calls `chainSelectionForBlock` for that block: [4](#0-3) 

**How the weight boost affects chain selection:**

`WeightedSelectView` computes `wsvTotalWeight = blockNo + wsvWeightBoost`. Chain selection calls `preferCandidate`, which switches to a candidate whenever its total weight exceeds the current chain's total weight: [5](#0-4) 

With `perasWeight = 15` from `mkPerasParams`, a single crafted certificate boosts a fork block by 15 weight units — enough to make a fork that is 15 blocks shorter than the honest chain appear heavier. [6](#0-5) 

---

### Impact Explanation

**Impact: High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker with a single peer connection can:
1. Send a `PerasCert` whose `pcCertBoostedBlock` points to any block already in the victim node's `VolatileDB` (e.g., a block on a minority fork).
2. The cert passes `validatePerasCert` unconditionally and is stored.
3. Chain selection is re-run for the boosted block with a weight advantage of 15.
4. If the fork is within 15 blocks of the honest chain tip, the node switches to the fork.

This violates the Peras security invariant that only certificates backed by a quorum of stake-weighted committee votes may influence chain selection. The attacker needs no stake, no keys, and no quorum — only a peer connection and knowledge of a block hash in the victim's VolatileDB.

---

### Likelihood Explanation

**Likelihood: Medium** (for a Peras-enabled testnet or private network where the object-diffusion mini-protocol is active).

- The Peras object-diffusion mini-protocol is a public peer-to-peer interface; any connected peer can send `PerasCert` messages.
- The validation stub is in the production code path (`makePerasCertPoolWriterFromChainDB`), not a test-only path.
- The only precondition is that the attacker knows a block hash present in the victim's VolatileDB, which is trivially obtainable via the ChainSync mini-protocol.
- On mainnet today, Peras is not yet activated, so the attack surface is limited to testnets or private networks running Peras-enabled builds.

---

### Recommendation

1. **Short term:** Replace the stub `validatePerasCert` with a real implementation that verifies: (a) the certificate carries a valid quorum of committee-member signatures, (b) each signing member is eligible per the current stake distribution, and (c) the boosted block point is a known, valid block on a chain that extends the node's immutable tip. Until this is done, the `TODO replace when actual plumbing is in place` comment in `makePerasCertPoolWriterFromChainDB` should be treated as a security blocker, not a deferred task.

2. **Long term:** Add property tests that send crafted `PerasCert` messages with arbitrary `pcCertBoostedBlock` values and assert that they are rejected when they lack a valid quorum proof, analogous to the existing `genFakeEligibilityWitness` tests for votes.

---

### Proof of Concept

On a private testnet with Peras object diffusion enabled:

1. Connect to a victim node as a peer.
2. Via ChainSync, learn a block hash `H` on a minority fork at block number `N` that is currently losing chain selection (e.g., the honest chain tip is at `N+14`).
3. Craft a `PerasCert` with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = BlockPoint <slot> H`.
4. Send it via the Peras cert object-diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
6. `chainSelSync` adds the cert and calls `chainSelectionForBlock` for block `H`.
7. The fork's `wsvTotalWeight = N + 15` now exceeds the honest chain's `wsvTotalWeight = N + 14 + 0`, so `preferCandidate` returns `ShouldSwitch`.
8. The victim node switches to the minority fork. [7](#0-6) [8](#0-7) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
