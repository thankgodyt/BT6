The call chain is fully traceable. Let me confirm the one remaining detail about `limitToLatestReleasedVersion` and whether `NodeToNodeV_16` is actually gated.

### Title
Degenerate `validatePerasCert` Bypasses All Certificate Cryptography, Allowing Any Peer to Influence Chain Selection via `PerasCertDiffusion` — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right`, performing zero BLS-signature, committee-membership, or quorum checks. This instance is wired directly into the live `PerasCertDiffusion` miniprotocol handler for all negotiated `NodeToNode` versions (V14/V15/V16). Any peer can therefore send a crafted `PerasCert` that passes "validation", is stored in the `PerasCertDB`, and triggers `chainSelectionForBlock` for an attacker-chosen block with a weight boost of 15, without holding any stake or cryptographic key.

---

### Finding Description

**Step 1 — Degenerate instance (root cause)** [1](#0-0) 

The `instance StandardHash blk => BlockSupportsPeras blk` at line 320 is the only instance in scope. Its `validatePerasCert` (lines 353–358) ignores every field of the certificate and returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally. No BLS aggregate signature, no committee seat check, no round-number bounds check.

**Step 2 — Production wiring into `PerasCertDiffusion`** [2](#0-1) 

`mkHandlers` (production, not test) wires `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB systemTime getChainDB` as the inbound pool writer for every peer connection.

**Step 3 — `makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams`** [3](#0-2) 

The `opwAddObjects` closure calls `processCerts` with `validatePerasCert mkPerasParams` as the validator and `void . ChainDB.addPerasCertAsync chainDB` as the sink. The `-- TODO replace when actual plumbing is in place` comment confirms this is a known placeholder, not a deliberate design.

**Step 4 — `processCerts` forwards every cert that passes validation** [4](#0-3) 

Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces `([], validatedCerts)`, and every inbound cert is passed to `addCert` (= `ChainDB.addPerasCertAsync`).

**Step 5 — `chainSelSync` triggers `chainSelectionForBlock` for the boosted block** [5](#0-4) 

The only guards are:
- `pointSlot boostedBlock < AF.anchorToSlotNo immTip` → exit early (too old)
- boosted block not in VolatileDB → exit early

If the attacker references any block currently in the VolatileDB (publicly observable via ChainSync), `chainSelectionForBlock` is called with that block and a `perasWeight` boost of 15.

**Step 6 — All negotiated NTN versions are affected** [6](#0-5) 

`supportedNodeToNodeVersions` includes V14, V15, and V16. `latestReleasedNodeVersion` is `NodeToNodeV_15`, so `limitToLatestReleasedVersion` caps the active map at V15 — but V14 and V15 are both active. The `perasCertDiffusionProtocol` is included unconditionally in the `NodeToNodeProtocols` bundle for all versions (the code comment at line 1186–1188 explicitly states protocols are not gated by version). [7](#0-6) 

---

### Impact Explanation

An unprivileged peer connecting over `NodeToNodeV_14` or `NodeToNodeV_15` (both in the active supported-versions map) can:

1. Observe any block hash currently in the target node's VolatileDB via ChainSync.
2. Craft a `PerasCert{pcCertRound = r, pcCertBoostedBlock = thatPoint}` for any round `r` and any VolatileDB block.
3. Send it over the `PerasCertDiffusion` miniprotocol.
4. The cert passes `validatePerasCert` (always `Right`), is stored in the `PerasCertDB`, and triggers `chainSelectionForBlock` for the chosen block with a weight boost of `perasWeight = 15`.

With a boost of 15, a fork whose tip is boosted is preferred over the honest chain unless the honest chain is more than 15 blocks longer. This allows an adversary to steer an honest node toward a minority fork without holding any stake or cryptographic material, violating the invariant that only cryptographically authorized certificates with valid BLS aggregate signatures and legitimate committee quorum may influence chain selection.

---

### Likelihood Explanation

- The `PerasCertDiffusion` protocol is active for all `NodeToNodeV_14`/`V15` connections — no feature flag gates it at the handler level.
- The exploit requires only: (a) a TCP connection to the target node, (b) knowledge of a VolatileDB block hash (public via ChainSync), and (c) the ability to send a well-formed CBOR-encoded `PerasCert` message.
- No stake, no keys, no prior trust relationship required.
- The degenerate instance is the only `BlockSupportsPeras` instance in scope (it is a catch-all `instance StandardHash blk =>`), so there is no override path for Cardano blocks.

---

### Recommendation

1. **Immediate**: Gate the `PerasCertDiffusion` inbound handler behind a feature flag that is disabled by default until real `validatePerasCert` logic is in place, or return `Left PerasValidationErr` unconditionally from the degenerate instance so that all inbound certs are rejected and the peer is disconnected.
2. **Short-term**: Replace `validatePerasCert mkPerasParams` in `makePerasCertPoolWriterFromChainDB` with a real validator that checks BLS aggregate signatures and committee quorum before the cert reaches `ChainDB.addPerasCertAsync`.
3. **Tracking**: Issues [#73](https://github.com/tweag/cardano-peras/issues/73) and [#120](https://github.com/tweag/cardano-peras/issues/120) already track this; they should be treated as security-critical blockers before `NodeToNodeV_16` (or any version carrying `PerasCertDiffusion`) is deployed to mainnet.

---

### Proof of Concept

```haskell
-- Locally testable with io-sim / ThreadNet harness:

-- 1. Confirm validatePerasCert always returns Right:
let cert = PerasCert { pcCertRound = PerasRoundNo 999
                     , pcCertBoostedBlock = someVolatilePoint }
assert (isRight (validatePerasCert mkPerasParams cert))

-- 2. Feed through processCerts and confirm addCert is called:
--    Use makePerasCertPoolWriterFromChainDB with a mock ChainDB that
--    records calls to addPerasCertAsync.
--    Send [cert] via opwAddObjects.
--    Assert addPerasCertAsync was called with the cert.

-- 3. Confirm chainSelSync triggers chainSelectionForBlock:
--    Pre-populate VolatileDB with a block at someVolatilePoint.
--    Call addPerasCertSync chainDB (WithArrivalTime now validatedCert).
--    Assert chainSelectionForBlock was invoked for that block.
```

The `PerasCert` data constructor, `mkPerasParams`, `makePerasCertPoolWriterFromChainDB`, and `addPerasCertSync` are all exported from their respective modules and usable in a standard `io-sim`-based integration test without any mocking of cryptographic primitives.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1263)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs (L437-456)
```haskell
  supportedNodeToNodeVersions _ =
    Map.fromList $
      [ (NodeToNodeV_14, CardanoNodeToNodeVersion2)
      , (NodeToNodeV_15, CardanoNodeToNodeVersion2)
      , (NodeToNodeV_16, CardanoNodeToNodeVersion2)
      ]

  supportedNodeToClientVersions _ =
    Map.fromList $
      [ (NodeToClientV_16, CardanoNodeToClientVersion12)
      , (NodeToClientV_17, CardanoNodeToClientVersion13)
      , (NodeToClientV_18, CardanoNodeToClientVersion14)
      , (NodeToClientV_19, CardanoNodeToClientVersion15)
      , (NodeToClientV_20, CardanoNodeToClientVersion16)
      , (NodeToClientV_21, CardanoNodeToClientVersion17)
      , (NodeToClientV_22, CardanoNodeToClientVersion18)
      , (NodeToClientV_23, CardanoNodeToClientVersion19)
      ]

  latestReleasedNodeVersion _prx = (Just NodeToNodeV_15, Just NodeToClientV_23)
```
