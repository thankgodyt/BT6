### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted target; the certificate passes "validation", is stored in the `PerasCertDB`, and immediately triggers chain selection for the boosted block, potentially causing the node to switch to a non-canonical fork it would never otherwise prefer.

---

### Finding Description

The universal `BlockSupportsPeras` instance (line 320) is explicitly labelled a "degenerate instance for all blks to get things to compile":

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

This stub is wired directly into the production inbound-certificate path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator for every batch of certificates received from a peer:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then calls this validator and, if it returns `Right` (which it always does), adds the certificate to the ChainDB: [3](#0-2) 

Once stored, `chainSelSync` processes the certificate and calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then computes `wsvTotalWeight` as `blockNo + weightBoost`, where `weightBoost` is the sum of all Peras boosts on the candidate fragment: [5](#0-4) 

Because `validatePerasCert` never checks: (a) committee membership of the signers, (b) cryptographic signatures on the certificate, (c) whether the certificate's round number is valid relative to the current chain state, (d) whether the boosted block is a legitimate voting target — any peer can inject a certificate that artificially inflates the weight of any block in the VolatileDB by `perasWeight` (currently 15) per injected certificate.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

A peer sends a `PerasCert` whose `pcCertBoostedBlock` points to the tip of a shorter fork already present in the node's VolatileDB. The certificate passes the stub validator, is stored, and triggers `chainSelectionForBlock` for that fork tip. The fork's `wsvTotalWeight` is now `blockNo(fork_tip) + 15`, which may exceed the honest chain's `blockNo(honest_tip) + 0`, causing the node to roll back to the adversarial fork. Multiple injected certificates (one per round number, since the DB deduplicates by round) multiply the boost. With `perasWeight = 15`, a fork that is 15 blocks shorter than the honest chain can be made to appear equally or more preferred.

---

### Likelihood Explanation

**High.** The object diffusion mini-protocol for Peras certificates is a standard peer-to-peer channel reachable by any connected node. No authentication, stake ownership, or privileged access is required to send a `PerasCert` message. The stub is in the universal production instance with an explicit `TODO` comment acknowledging the missing validation. The chain selection side-effect is unconditional once the certificate is stored.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that checks:
1. The certificate's committee membership and cryptographic signatures against the stake distribution for the relevant epoch.
2. That the certificate's round number is within the valid window (`perasCertMaxRounds`) relative to the current chain tip.
3. That the boosted block is a legitimate voting target (age ≥ `perasBlockMinSlots`, not already immutable).

Until real validation is implemented, the object diffusion server for Peras certificates should not be enabled in production builds, or inbound certificates should be silently dropped rather than accepted unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a victim node as a standard peer.
2. Attacker observes that the victim's VolatileDB contains a fork block `B_fork` at `blockNo = N-1` while the honest chain tip is at `blockNo = N`.
3. Attacker crafts `PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B_fork) }` for any fresh round number `R` not yet in the victim's DB.
4. Attacker sends this certificate via the Peras object diffusion mini-protocol.
5. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams` returns `Right` unconditionally.
6. Certificate is stored; `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
7. `chainSelSync` calls `chainSelectionForBlock` for `B_fork`.
8. `weightedSelectView` computes `wsvTotalWeight(fork) = (N-1) + 15 = N+14` vs `wsvTotalWeight(honest) = N + 0 = N`.
9. `preferCandidate` returns `ShouldSwitch`; the node rolls back to the adversarial fork. [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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
