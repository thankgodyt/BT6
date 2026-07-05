### Title
Degenerate `validatePerasCert` Unconditionally Accepts Any Peras Certificate via Live ObjectDiffusion Path — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The global `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound `PerasCert`, performing no signature, round-number, or boosted-block-point check. This stub is wired directly into the production NodeToNode `hPerasCertDiffusionClient` handler via `makePerasCertPoolWriterFromChainDB`. Any peer speaking NodeToNodeV_16 can submit a structurally well-formed but entirely fabricated certificate, have it accepted without any cryptographic check, and cause the node to run chain selection with a weight boost of 15 on an adversary-chosen block.

---

### Finding Description

**Root cause — degenerate instance:** [1](#0-0) 

The `instance StandardHash blk => BlockSupportsPeras blk` at line 320 is explicitly labelled a temporary placeholder (TODO, issue #73). Its `validatePerasCert` at lines 353–358 ignores the certificate entirely and returns `Right` unconditionally:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
```

No signature is checked, no committee membership is verified, no round-number bounds are enforced, and no boosted-block-point is authenticated.

**Production wiring — `makePerasCertPoolWriterFromChainDB`:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` (the production writer, not the test-only `CertDB` variant) passes `validatePerasCert mkPerasParams` as the validation function at line 126. This is not a test path — the doc-comment at line 111 explicitly distinguishes it from the test-only `makePerasCertPoolWriterFromCertDB`.

**NodeToNode handler wiring:** [3](#0-2) 

`hPerasCertDiffusionClient` at line 382 calls `makePerasCertPoolWriterFromChainDB systemTime getChainDB` directly. This handler is registered unconditionally in both `initiator` (line 1214) and `initiatorAndResponder` (line 1259) for NodeToNodeV_16. [4](#0-3) 

**`processCerts` — the inbound gate:** [5](#0-4) 

`processCerts` calls `validateCert` (which resolves to the degenerate instance) on each inbound cert. Because the degenerate instance always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is added to the ChainDB via `addPerasCertAsync`.

**Chain selection impact:** [6](#0-5) 

`chainSelSync` for `ChainSelAddPerasCert` adds the cert to the `PerasCertDB` and, if the boosted block is in the VolatileDB but not on the current chain, calls `chainSelectionForBlock` for that block. The `PerasWeightSnapshot` is updated with a boost of `PerasWeight 15` (from `mkPerasParams`), and `preferAnchoredCandidate` / `compareAnchoredFragments` use this snapshot to prefer the boosted fork. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can:

1. Connect to a victim node using NodeToNodeV_16 and negotiate the `perasCertDiffusionProtocol`.
2. Craft a `PerasCert { pcCertRound = <any>, pcCertBoostedBlock = <target block point> }` for any block in the victim's VolatileDB.
3. Send it via the ObjectDiffusion inbound path.
4. `validatePerasCert mkPerasParams` returns `Right` unconditionally; the cert is stored and `addPerasCertAsync` is called.
5. Chain selection runs for the boosted block with an extra weight of 15, potentially causing the node to switch to an adversary-chosen fork.

This directly violates the invariant that only certificates backed by a quorum of authenticated committee votes may influence chain selection. The impact matches **Critical: Bypass of certificate/signature validation that enables unauthorized certificate acceptance** and **High: Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The ObjectDiffusion miniprotocol is fully wired into the production NodeToNode application bundle for NodeToNodeV_16. The `featureFlags` parameter is passed to `nodeToNodeProtocols` in `ouroboros-network` (outside this repo), and `getLocalPerasSupport rnFeatureFlags version` at `Node.hs:1094` is used in version-data negotiation. Whether the network layer gates the `perasCertDiffusionProtocol` mini-protocol on a feature flag is not visible in this repository. However:

- The consensus-layer handler is wired unconditionally.
- The comment at `NodeToNode.hs:1186–1188` states: *"network currently doesn't enable protocols conditional on the protocol version"*.
- The code is in a pre-release development branch where Peras is being actively integrated; any node built from this branch and running NodeToNodeV_16 is exposed.

Likelihood is **High** for any node running this codebase with NodeToNodeV_16 enabled, regardless of whether Peras is "disabled" at the ledger level (the cert diffusion and chain-selection boost operate independently of ledger-era Peras activation).

---

### Recommendation

1. **Immediate**: Gate `makePerasCertPoolWriterFromChainDB` (and the `hPerasCertDiffusionClient` handler) behind a runtime check that returns an error or no-ops until a real `validatePerasCert` is in place. Alternatively, disable the `perasCertDiffusionProtocol` mini-protocol entirely until the HFC plumbing is complete.
2. **Short-term**: Replace the degenerate `instance StandardHash blk => BlockSupportsPeras blk` with a proper per-block-type instance that performs cryptographic certificate validation (committee membership, quorum threshold, round-number bounds, boosted-block-point authentication).
3. **Tracking**: The existing TODO references (issues #73 and #120) should be treated as security-critical blockers before any release that enables NodeToNodeV_16 with Peras cert diffusion.

---

### Proof of Concept

Using `io-sim` or the existing `Test.Consensus.MiniProtocol.ObjectDiffusion.PerasCert.Smoke` harness:

```haskell
-- 1. Construct a forged certificate pointing at an adversary-chosen block
let forgedCert = PerasCert
      { pcCertRound      = PerasRoundNo 999
      , pcCertBoostedBlock = BlockPoint (SlotNo 42) adversaryBlockHash
      }

-- 2. Call validatePerasCert with the degenerate instance
let result = validatePerasCert mkPerasParams forgedCert
-- result == Right (ValidatedPerasCert { vpcCert = forgedCert, vpcCertBoost = PerasWeight 15 })
-- No error, no signature check, no round-number check.

-- 3. Feed through processCerts (as the ObjectDiffusion inbound path does)
processCerts systemTime alreadyInDbSTM (validatePerasCert mkPerasParams) addCert [forgedCert]
-- The cert is accepted and stored.

-- 4. Confirm rejection with a real validating instance substituted
-- (replace validatePerasCert with one that checks committee signatures)
-- => Left PerasValidationErr
```

The assertion at step 2 holds on unmodified code. Step 4 confirms the invariant is only enforced once the real instance is wired in.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1263)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
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
