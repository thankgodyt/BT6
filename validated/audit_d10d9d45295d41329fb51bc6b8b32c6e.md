### Title
Unprivileged Peer Can Inject Arbitrary Peras Certificates to Manipulate Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate received, performing zero cryptographic or semantic validation. Any peer reachable via the `PerasCertDiffusion` miniprotocol can inject crafted `PerasCert` objects that are stored in the `PerasCertDB` and applied as weight boosts in chain selection, causing an honest node to prefer a non-canonical adversarially-boosted chain over the honest chain.

### Finding Description

**Root cause — stub validation that always succeeds:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for accepting inbound certificates. The only deployed instance is the catch-all degenerate instance:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
```

This instance matches every block type (`instance StandardHash blk => BlockSupportsPeras blk`) and returns `Right` unconditionally — no signature check, no quorum check, no round-number plausibility check, no committee membership check. [1](#0-0) 

**Entry point — the PerasCert diffusion miniprotocol:**

The production node wires the inbound side of the `PerasCertDiffusion` miniprotocol in `NodeToNode.hs`. Any peer connecting on `NodeToNodeV_16+` can send `PerasCert` objects through this channel:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

**Validation call-site — always passes:**

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function. Because `validatePerasCert` always returns `Right`, every cert in every batch passes:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

**Chain selection side-effect — boost applied:**

`addPerasCertAsync` enqueues the cert into the `ChainSelQueue`. The background `chainSelSync` handler stores it in `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Weight snapshot — boost feeds into `preferAnchoredCandidate`:**

`implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certs. When this snapshot is non-empty, `preferAnchoredCandidate` switches from the standard length-based comparison to a `weightedSelectView` comparison that adds the Peras boost to the chain's total weight:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      Just (..., oursSuffix, candSuffix) ->
        case preferCandidate
          (projectChainOrderConfig cfg)
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix) of
``` [5](#0-4) 

**Complete exploit path:**

1. Attacker connects to victim node via `NodeToNodeV_16+`.
2. Attacker sends crafted `PerasCert` objects, each specifying `pcCertRound = R` and `pcCertBoostedBlock = P` where `P` is a block on an adversarial fork that the victim has already received (or will receive).
3. `validatePerasCert` returns `Right` for every cert; each cert is stored in `PerasCertDB` with `vpcCertBoost = PerasWeight 15`.
4. `PerasWeightSnapshot` accumulates `N × 15` weight for the adversarial fork's blocks.
5. `preferAnchoredCandidate` now prefers the adversarially-boosted fork over the honest chain, causing the victim to switch to the adversarial chain.
6. The attacker can inject one cert per round number (deduplication is by `PerasRoundNo`), so with many rounds available the cumulative boost can be arbitrarily large.

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker with no stake and no keys can cause a victim node to permanently prefer an adversarial fork over the honest chain by injecting forged Peras certificates. The `PerasWeight 15` boost per certificate means that with enough injected certs the adversarial chain's weighted length exceeds the honest chain's, causing the node to switch forks. This violates the core Ouroboros chain-selection invariant and constitutes a consensus safety failure: the victim node diverges from the honest chain without any cryptographic justification.

### Likelihood Explanation

Any peer that can establish a `NodeToNodeV_16+` connection to the victim node can trigger this. No stake, no keys, no privileged access is required. The `PerasCertDiffusion` miniprotocol is open to all peers by design. The attacker only needs to know the hash of a block on their adversarial fork (or any block in the victim's VolatileDB) to craft a valid-looking cert. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known incomplete stub, not a deliberate design choice.

### Recommendation

1. **Immediate**: Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature, checks committee membership, verifies quorum stake threshold, and validates the round number against the current ledger state. The concrete certificate type in `Ouroboros.Consensus.Peras.Cert.V1` already defines the necessary fields (`pcSignature`, `pcVoters`) for this.
2. **Short-term**: Until real validation is in place, gate the `PerasCertDiffusion` inbound handler so that it rejects all inbound certs (returns an error or disconnects) rather than accepting them unconditionally.
3. **Structural**: The `validatePerasCert` call-site in `makePerasCertPoolWriterFromChainDB` must receive the actual `PerasCfg` derived from the current ledger state (committee selection data, stake distribution) rather than the hardcoded `mkPerasParams` default.

### Proof of Concept

```
Preconditions:
  - Victim node running with NodeToNodeV_16+ support and Peras enabled.
  - Attacker has a network connection to the victim (standard peer).
  - Attacker has previously sent (or will send) a block B on an adversarial fork
    that the victim has stored in its VolatileDB.

Steps:
  1. Attacker connects to victim via NodeToNodeV_16+.
  2. Attacker sends N PerasCert objects via the PerasCertDiffusion miniprotocol:
       cert_i = PerasCert { pcCertRound = i, pcCertBoostedBlock = point(B) }
     for i = 1 .. N.
  3. Each cert passes validatePerasCert (returns Right unconditionally).
  4. Each cert is stored in PerasCertDB with boost = PerasWeight 15.
  5. PerasWeightSnapshot now contains point(B) -> PerasWeight (N*15).
  6. chainSelectionForBlock is triggered for B.
  7. preferAnchoredCandidate computes:
       weightedSelectView of adversarial chain = length + N*15
       weightedSelectView of honest chain      = length + 0
     If N*15 > (honest_length - adversarial_length), victim switches to adversarial fork.

Expected outcome: victim node selects the adversarial chain containing B,
diverging from the honest chain without any legitimate quorum of stake.
``` [6](#0-5) [7](#0-6) [4](#0-3) [8](#0-7) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
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
