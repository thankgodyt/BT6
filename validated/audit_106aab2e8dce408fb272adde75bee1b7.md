### Title
Degenerate `validatePerasCert` Stub Unconditionally Accepts All Inbound Peras Certificates, Enabling Fake-Certificate Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole `BlockSupportsPeras` instance in the codebase is a deliberate stub that makes `validatePerasCert` unconditionally return `Right` for every certificate it receives, skipping all cryptographic and semantic checks. The production Peras-certificate diffusion inbound path calls this stub directly, so any unprivileged peer can inject arbitrarily crafted certificates that pass "validation", get stored in the `PerasCertDB`, and trigger chain selection with a fabricated weight boost — potentially causing an honest node to abandon the canonical chain.

---

### Finding Description

**Root cause — stub `validatePerasCert` in the universal `BlockSupportsPeras` instance**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` contains the only `BlockSupportsPeras` instance in the repository. It is explicitly labelled a "degenerate instance for all blks to get things to compile":

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
``` [1](#0-0) 

The function accepts **any** `PerasCert` value without checking:
- the aggregate BLS signature over the election identifier and boosted block hash,
- whether the claimed voters are eligible committee members,
- whether the votes reach the quorum threshold,
- whether the round number is plausible, or
- whether the boosted block actually exists on a valid chain.

**Production inbound path wires this stub directly**

`makePerasCertPoolWriterFromChainDB` — the production writer used when Peras is enabled — passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection is triggered by the injected certificate**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes it: the certificate is stored in the `PerasCertDB`, and if the boosted block is present in the `VolatileDB`, `chainSelectionForBlock` is called for it: [4](#0-3) 

`preferAnchoredCandidate` then uses `weightedSelectView`, which sums `weightBoostOfFragment` over the candidate fragment. Each accepted fake certificate contributes `perasWeight mkPerasParams = PerasWeight 15` to the boosted block's chain weight: [5](#0-4) [6](#0-5) 

**`getPerasCertInBlock` is also a stub (always `Nothing`)**

The same degenerate instance makes `getPerasCertInBlock _ = Nothing`, so certificates embedded in blocks are never extracted. This is a second missing-functionality defect in the same stub, acknowledged in the test code: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` where `p` is the point of any block on an adversary-controlled fork that is present in the victim's `VolatileDB`.
2. Send it via the Peras-cert diffusion miniprotocol.
3. The victim's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The cert is stored in the `PerasCertDB` and `chainSelectionForBlock` is triggered.
5. The adversary's fork now carries `+15` weight per injected certificate. By injecting one certificate per Peras round (round length = 90 slots), the adversary can accumulate weight faster than the honest chain grows (1 weight per block, ~1 block per slot on average), making a fork that is up to 14 blocks shorter appear heavier than the honest chain.
6. The node switches to the adversary's fork — accepting an invalid or non-canonical chain.

This constitutes a **bypass of certificate validation** enabling unauthorized chain-selection manipulation: an honest node can be made to prefer a non-canonical chain without the adversary holding any stake or keys.

---

### Likelihood Explanation

- Peras is currently an experimental feature gated by `rnFeatureFlags` and disabled by default on mainnet. The CHANGELOG explicitly notes: *"if Peras is disabled (which is the default), there is no observable difference."*
- On any private testnet or development environment where Peras is enabled (the intended deployment target for this code), the attack is immediately exploitable by any connected peer with no special privileges.
- The attack requires only a valid network connection and knowledge of a block hash in the victim's VolatileDB (obtainable via ChainSync headers).
- The TODO comments (`-- TODO replace when actual plumbing is in place`) confirm this is a known incomplete state, not a deliberate design choice, making it a realistic near-term risk as Peras moves toward production.

---

### Recommendation

1. **Replace the stub `validatePerasCert`** with a real implementation that verifies the aggregate BLS signature, checks committee membership eligibility, and confirms the quorum threshold is met before returning `Right`. This is tracked at https://github.com/tweag/cardano-peras/issues/120.

2. **Replace the stub `getPerasCertInBlock`** with an implementation that extracts certificates embedded in blocks via the HFC plumbing, tracked at https://github.com/tweag/cardano-peras/issues/73.

3. **Gate `makePerasCertPoolWriterFromChainDB` on Peras being fully implemented**: until real validation is in place, the inbound cert diffusion path should either be disabled entirely or should reject all certificates with a hard error rather than accepting them unconditionally.

4. **Add a compile-time or runtime guard** that prevents the degenerate instance from being used in any production code path, e.g., by requiring a separate `ValidatedBlockSupportsPeras` evidence type that can only be constructed by the real implementation.

---

### Proof of Concept

On a private testnet with Peras enabled (`rnFeatureFlags` includes the Peras flag):

1. Connect a malicious peer to the victim node via the node-to-node protocol.
2. Observe (via ChainSync) a block hash `H` at point `p` on a fork that is 14 blocks behind the honest tip.
3. Send a `PerasCert { pcCertRound = 1, pcCertBoostedBlock = p }` via the Peras-cert diffusion miniprotocol.
4. The victim calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
5. `chainSelSync` triggers `chainSelectionForBlock` for block `H`.
6. `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork: `blockNo(H) + 15`. If `blockNo(H) + 15 > blockNo(honest_tip)`, the node switches to the fork.
7. Repeat with additional fake certificates (one per round) to overcome larger deficits.

The degenerate instance at lines 353–358 of `SupportsPeras.hs` is the single necessary and sufficient vulnerable step; no other code change is required. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/unstable-consensus-testlib/Test/Ouroboros/Storage/TestBlock.hs (L626-631)
```haskell
                  -- NOTE: this bypasses the degenerate global implementation of
                  -- 'BlockSupportsPeras.getPerasCertInBlock' for 'TestBlock',
                  -- which currently always returns 'Nothing'.
                  --
                  -- TODO: refactor this to use 'getPerasCertInBlock' after the
                  -- HFC plumbing for 'BlockSupportsPeras' is in place.
```
