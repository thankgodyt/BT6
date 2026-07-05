### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Always Returning `Right` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` method is an explicit stub that unconditionally returns `Right` for every certificate it receives, performing zero validation. When Peras is enabled, any unprivileged peer can inject crafted `PerasCert` objects via the ObjectDiffusion protocol. These certificates are accepted without any quorum, signature, or round-validity check, and are immediately stored in the `PerasCertDB` and used to trigger chain selection with artificially inflated weight.

---

### Finding Description

The `BlockSupportsPeras` instance for `StandardHash blk` (the universal production instance, since `type PerasCfg blk = PerasParams`) implements `validatePerasCert` as a stub that always succeeds:

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

This stub is called directly from the ObjectDiffusion inbound path in `makePerasCertPoolWriterFromChainDB`, which processes certificates received from remote peers:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

Once accepted, the certificate is stored in the `PerasCertDB` via `implAddCert`, which performs no further content validation: [3](#0-2) 

The stored certificate then triggers `chainSelectionForBlock` via `chainSelSync`, which re-evaluates chain selection using the updated `PerasWeightSnapshot`: [4](#0-3) 

The weight boost applied to the boosted block is taken from the local `perasWeight params` (e.g., 15 by default in `mkPerasParams`), not from the certificate itself. The `PerasParams` record has no bounds validation on any of its fields — `perasWeight`, `perasQuorumStakeThreshold`, `perasRoundLength`, etc. are all plain newtypes over `Word64` or `Rational` with no invariant enforcement: [5](#0-4) 

The `stakeAboveThreshold` function, which gates certificate forging from votes, also performs no bounds check on `perasQuorumStakeThreshold` — if it were 0, any single vote would satisfy quorum: [6](#0-5) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate checks enabling unauthorized certificate acceptance.**

When Peras is enabled (via `rnFeatureFlags` / `eraPerasRoundLength`), an unprivileged peer can:

1. Send a crafted `PerasCert` naming any `pcCertBoostedBlock` (any block in the VolatileDB) and any `pcCertRound`.
2. The stub `validatePerasCert` accepts it unconditionally.
3. The certificate is stored in `PerasCertDB` and the boosted block receives `perasWeight` additional chain weight (e.g., 15).
4. Chain selection is re-triggered. If the boosted block is on a competing fork, the node may switch to that fork.
5. Since `PerasCertDB` stores one certificate per round, an attacker sending certificates across many rounds can accumulate weight on a non-canonical chain, potentially exceeding the rollback threshold `k` in weight terms.

The `SecurityParam` in Peras is interpreted as a maximum rollback *weight*, not just block count: [7](#0-6) 

With `perasWeight = 15` and `k = 2160`, an attacker injecting 144 certificates across distinct rounds accumulates enough weight to make a competing chain appear heavier than the honest chain by the full security parameter, causing the node to irreversibly prefer a non-canonical chain.

---

### Likelihood Explanation

**Likelihood: Medium.**

Peras is currently gated behind `rnFeatureFlags` and `eraPerasRoundLength = NoPerasEnabled` by default. It is not active on Cardano mainnet today. However:

- The code is present in production files and is the only `BlockSupportsPeras` instance.
- Private testnets and staging environments with Peras enabled are explicitly in scope ("private-testnet sequence").
- The attack requires no special privileges — any connected peer can send `PerasCert` objects via the ObjectDiffusion protocol.
- The stub is self-documented as incomplete (TODO), meaning it is expected to be replaced, but until it is, any deployment with Peras enabled is fully exposed.

---

### Recommendation

1. **Implement actual certificate validation** in `validatePerasCert`: verify that the certificate was formed by a genuine quorum of stake holders (checking BLS aggregate signatures or equivalent), that the round number is within the valid window, and that the boosted block is a known valid block.
2. **Add bounds validation to `PerasParams`**: enforce `perasQuorumStakeThreshold > 0 && perasQuorumStakeThreshold <= 1`, `perasWeight > 0`, `perasRoundLength > 0`, and `perasCertArrivalThreshold < perasRoundLength`. This mirrors the `_validReserveWeight` pattern from the zBanc fix and prevents silent misconfiguration from corrupting quorum semantics.
3. **Gate the ObjectDiffusion inbound path** on Peras being actually enabled before accepting certificates from peers.

---

### Proof of Concept

On a private testnet with Peras enabled (`eraPerasRoundLength = PerasEnabled (PerasRoundLength 90)`):

1. Attacker peer connects to an honest node.
2. Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = <point on competing fork> }` via the ObjectDiffusion cert diffusion channel.
3. `makePerasCertPoolWriterFromChainDB` calls `processCerts ... (validatePerasCert mkPerasParams) ...`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }` unconditionally.
5. `implAddCert` stores the certificate; `chainSelSync` triggers chain selection for the boosted block.
6. The competing fork gains 15 weight units. Repeating across 144 distinct rounds gives the competing fork weight ≥ k = 2160, causing the honest node to permanently prefer the attacker's chain. [8](#0-7) [1](#0-0)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-132)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
  deriving (Show, Eq, Generic, NoThunks)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-44)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
  deriving (Eq, Generic, NoThunks, ToCBOR, FromCBOR)
  deriving Show via Quiet SecurityParam

-- | The maximum amount of weight we can roll back.
maxRollbackWeight :: SecurityParam -> PerasWeight
maxRollbackWeight = PerasWeight . unNonZero . maxRollbacks
```
