### Title
Peras Certificate Validation is a No-Op, Allowing Any Peer to Inject Arbitrary Chain-Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the degenerate `BlockSupportsPeras` instance unconditionally accepts every inbound `PerasCert` without performing any cryptographic or semantic checks. Because this is the instance wired into the production certificate-diffusion path, an unprivileged peer can send a crafted certificate that boosts an arbitrary block on a competing fork, causing the honest node to prefer that fork in chain selection.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate validation. The codebase ships a single catch-all instance for all `StandardHash blk` types, explicitly labelled a "degenerate instance … to get things to compile":

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

Every `PerasCert` — regardless of its `pcCertRound`, `pcCertBoostedBlock`, aggregate BLS signature, quorum membership, or any other field — is returned as `Right` with the full `perasWeight` boost (`PerasWeight 15` from `mkPerasParams`).

This stub is the function passed directly into the production certificate-diffusion writer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
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

`processCerts` calls `validateCert` on each inbound certificate; if all pass (which they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. `chainSelSync` then processes it: it looks up the boosted block in the VolatileDB and calls `chainSelectionForBlock` for it, using the now-inflated `PerasWeightSnapshot`: [4](#0-3) 

Chain selection compares fragments using `WeightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost`. A single injected certificate adds `PerasWeight 15` to the boosted block's fork: [5](#0-4) 

The analog to the UniV3 bug is exact: just as the staking contract never checked that the underlying tokens of a position were USDC/DYAD, `validatePerasCert` never checks that the underlying components of a certificate (committee membership, aggregate signature, quorum, round validity) are legitimate.

---

### Impact Explanation

**Impact: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

An attacker who can connect to a node via the Peras certificate object-diffusion mini-protocol can:

1. Send one crafted `PerasCert` per Peras round, each pointing `pcCertBoostedBlock` at a block on an adversarial fork.
2. Each certificate passes `validatePerasCert` unconditionally and is stored in the `PerasCertDB`.
3. The accumulated weight boost (`PerasWeight 15` per certificate) is applied to the adversarial fork's `WeightedSelectView`.
4. Once the adversarial fork's total weight exceeds the honest chain's total weight, `chainSelectionForBlock` switches the node to the adversarial fork.

The `SecurityParam` in Peras is interpreted as maximum rollback *weight*, not just block count: [6](#0-5) 

With `k = 2160` and `perasWeight = 15`, an attacker needs only `ceil(2160 / 15) = 144` crafted certificates (one per round) to accumulate enough weight to force a rollback of the maximum depth, causing the node to permanently adopt an adversarial chain.

---

### Likelihood Explanation

**Likelihood: High.**

- The entry point is the public Peras certificate object-diffusion mini-protocol, reachable by any peer that can establish a connection.
- No keys, stake, or privileged access are required — only the ability to send a well-formed CBOR-encoded `PerasCert` message.
- The `PerasCert` type is simple (round number + block point); crafting one requires no cryptographic material.
- The `processCerts` function explicitly disconnects peers that send *invalid* certificates, but since `validatePerasCert` never returns `Left`, no certificate is ever invalid.
- The TODO comment at the call site (`-- TODO replace when actual plumbing is in place`) confirms this is a known placeholder, not a deliberate security decision.

---

### Recommendation

Replace the no-op `validatePerasCert` stub with a real implementation that verifies:

1. **Committee membership**: each voter in `pcCertVoters` must be a member of the Peras voting committee for the given round.
2. **Quorum**: the aggregate stake of the voters must exceed `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
3. **Aggregate BLS signature**: `pcSignature` must be a valid aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` by the claimed voters, using the concrete `implVerifyCert` logic already implemented in `Ouroboros.Consensus.Committee.EveryoneVotes` and `Ouroboros.Consensus.Committee.WFALS`.
4. **Round validity**: `pcCertRound` must correspond to a valid, non-expired Peras round relative to the current ledger state.

Until the real implementation is wired in, the Peras certificate diffusion path should be disabled or gated behind a feature flag that is off by default, preventing unauthenticated certificates from influencing chain selection.

---

### Proof of Concept

An attacker peer:

1. Connects to the target node via the Peras certificate object-diffusion mini-protocol.
2. Identifies a competing fork tip `B` in the VolatileDB (e.g., by observing headers via ChainSync).
3. Constructs `n` certificates:
   ```
   PerasCert { pcCertRound = r_i, pcCertBoostedBlock = point(B) }
   ```
   for rounds `r_1 … r_n`, where `n = ceil(k / perasWeight) = ceil(2160 / 15) = 144`.
4. Sends all `n` certificates in a single batch to `processCerts`.
5. `validatePerasCert mkPerasParams cert` returns `Right` for each — no signature, no quorum, no membership check.
6. Each certificate is stored in `PerasCertDB` and triggers `chainSelSync → chainSelectionForBlock`.
7. After all certificates are processed, `weightBoostOfFragment` returns `PerasWeight (144 * 15) = PerasWeight 2160` for the adversarial fork.
8. `WeightedSelectView` now shows the adversarial fork's total weight ≥ the honest chain's total weight, and `chainSelectionForBlock` switches the node to the adversarial fork. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-106)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
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
