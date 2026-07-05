### Title
Stub `validatePerasCert` Always Accepts Any Inbound Peras Certificate, Enabling Unprivileged Chain-Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no cryptographic or semantic checks. This stub is wired directly into the production node-to-node Peras certificate inbound handler (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject a crafted `PerasCert` naming an arbitrary block as the boosted block, causing the victim node to apply a fraudulent weight boost to that block and potentially switch to a non-canonical chain.

### Finding Description

**Root cause — stub validator always succeeds:**

The `BlockSupportsPeras` universal instance in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional `Right`:

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

No committee membership check, no aggregate BLS signature verification, no round-number range check, and no quorum threshold check is performed. The `PerasValidationErr` type is also a stub with a single opaque constructor, confirming no real error path exists yet. [2](#0-1) 

**Production inbound handler uses the stub:**

`makePerasCertPoolWriterFromChainDB` — the writer used by the live node-to-node Peras certificate diffusion client — passes `validatePerasCert mkPerasParams` directly as the validation function to `processCerts`:

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
``` [3](#0-2) 

**`processCerts` adds every cert that passes validation:**

`processCerts` partitions results and adds all `Right` values to the ChainDB. Because the stub always returns `Right`, every inbound certificate is added: [4](#0-3) 

**Network entry point — reachable by any peer:**

The production node-to-node handler wires `makePerasCertPoolWriterFromChainDB` into `objectDiffusionInbound`, which is the inbound side of the Peras certificate ObjectDiffusion mini-protocol, reachable by any connecting peer: [5](#0-4) 

**Chain selection consequence:**

Once a `ValidatedPerasCert` is added to the ChainDB via `addPerasCertAsync`, `chainSelSync` processes it: it stores the cert in the `PerasCertDB`, updates the `PerasWeightSnapshot` with a boost for `pcCertBoostedBlock`, and then triggers chain selection for the boosted block. If the boosted block is on a fork, the node may switch to that fork: [6](#0-5) 

The `preferAnchoredCandidate` function uses `weightedSelectView` to compare chains by `wsvTotalWeight = blockNo + weightBoost`, so a sufficiently large injected boost can make a shorter fork appear heavier than the honest chain: [7](#0-6) 

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker with a standard node-to-node connection can craft a `PerasCert` naming any block in the victim's VolatileDB as `pcCertBoostedBlock`. The victim node applies a `perasWeight`-sized boost to that block without any verification. If the attacker targets a block on a minority fork, the victim's chain selection may switch to that fork, diverging from the honest majority chain. Because the `PerasWeightSnapshot` accumulates boosts additively and the attacker can send one certificate per round number (deduplicated only by round, not by content), repeated injections across different round numbers can stack boosts on the same block, making the attack reliable even against a well-connected honest node.

### Likelihood Explanation

**High.** The Peras certificate ObjectDiffusion mini-protocol is enabled in the production node-to-node handler and is reachable by any peer that connects. No stake, key material, or privileged access is required. The attacker only needs to construct a valid CBOR-encoded `PerasCert` message (two fields: a round number and a block point), which is trivially achievable. The only existing guard — deduplication by round number — does not prevent an attacker from using a fresh round number for each injection.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The aggregate BLS signature over `(electionId, candidate)` using the public keys of the claimed committee members.
2. That the claimed voters form a valid quorum (total stake ≥ threshold) according to the current committee selection.
3. That the certificate's round number falls within the valid acceptance window.

Until the real implementation is in place, the inbound handler should reject all externally received certificates (e.g., by substituting a validator that always returns `Left PerasValidationErr`) rather than accepting them unconditionally.

### Proof of Concept

1. Attacker connects to a victim node via the node-to-node protocol and negotiates the Peras certificate ObjectDiffusion mini-protocol.
2. Attacker observes (via ChainSync) that the victim's VolatileDB contains a block `B` on a minority fork at `Point (SlotNo s, Hash h)`.
3. Attacker crafts a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s h }` for a fresh round number `r` not yet in the victim's `PerasCertDB`.
4. Attacker sends this certificate via the ObjectDiffusion protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
6. The cert is passed to `ChainDB.addPerasCertAsync`.
7. `chainSelSync` adds the cert to `PerasCertDB`, updates `PerasWeightSnapshot` with boost `perasWeight` for block `B`, and calls `chainSelectionForBlock` for `B`.
8. `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork containing `B`; if `blockNo(fork_tip) + perasWeight > blockNo(honest_tip)`, the victim switches to the attacker's fork.
9. Repeating with additional round numbers stacks boosts, making the attack succeed even against a longer honest chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-348)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
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
