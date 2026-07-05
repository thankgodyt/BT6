### Title
Peras Certificate Validation Bypass via Unconditional `validatePerasCert` Stub — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` method unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. This stub is wired directly into the production Peras certificate diffusion inbound path. Any unprivileged peer can therefore inject an arbitrary, cryptographically invalid Peras certificate that is accepted, stored in the `PerasCertDB`, and used to trigger chain selection for an attacker-chosen block — mirroring the M-07 pattern of accepting an object without verifying it satisfies the required interface, with the consequence that the downstream operation (chain selection) proceeds on a fraudulent basis.

---

### Finding Description

**Root cause — `SupportsPeras.hs` lines 318–358**

A single, overlapping instance covers every `StandardHash blk`:

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

No committee membership check, no aggregate BLS signature verification, no round-number sanity check, and no boosted-block existence check is performed. The function always returns `Right`.

**Production wiring — `PerasCert.hs` lines 118–133**

`makePerasCertPoolWriterFromChainDB`, the function used by the live node-to-node handler, passes this stub directly as the `validateCert` argument to `processCerts`:

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

**`processCerts` logic — `PerasCert.hs` lines 164–173**

Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces an empty error list, so every certificate is unconditionally forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Chain-selection consequence — `ChainSel.hs` lines 483–531**

`addPerasCertAsync` enqueues the accepted certificate for `chainSelSync`, which adds it to the `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block, giving it the full Peras weight boost:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  -- Trigger chain selection for the boosted block.
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Node-to-node handler wiring — `NodeToNode.hs` lines 375–383**

The production inbound handler for the `PerasCertDiffusion` mini-protocol uses `makePerasCertPoolWriterFromChainDB`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

---

### Impact Explanation

An unprivileged peer connected via the `PerasCertDiffusion` mini-protocol can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to trigger chain selection for the attacker-chosen block. The boosted block receives the full `perasWeight` boost. If the attacker has previously delivered a valid block to the node's `VolatileDB` (via normal `BlockFetch`), they can now cause the node to re-evaluate and potentially switch to a fork anchored at that block — a chain selection error driven entirely by a fraudulent certificate. This is a direct bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and non-canonical chain preference, matching the **Critical** impact tier (bypass of Peras certificate checks) and the **High** impact tier (chain selection bug allowing a non-canonical chain preference).

---

### Likelihood Explanation

The attack requires only a standard peer connection. No stake, no keys, and no privileged access are needed. The `PerasCertDiffusion` mini-protocol is active in the production node-to-node handler. The attacker only needs to (1) deliver one valid block via `BlockFetch` so it lands in the `VolatileDB`, then (2) send a `PerasCert` naming that block's hash. Both steps are reachable from an unprivileged network peer.

---

### Recommendation

1. **Replace the stub immediately.** `validatePerasCert` must perform full aggregate BLS signature verification against the committee's public keys, verify committee membership and seat indices, and check that the round number and boosted block point are within valid bounds. The concrete `PerasCert` type in `Peras.Cert.V1` already carries the necessary fields (`pcSignature`, `pcVoters`, `pcRoundNo`, `pcBoostedBlock`).

2. **Gate the diffusion handler.** Until real validation is in place, the `hPerasCertDiffusionClient` handler should reject all inbound certificates (return a permanent error or no-op writer) rather than silently accepting them.

3. **Remove the overlapping catch-all instance.** The `instance StandardHash blk => BlockSupportsPeras blk` instance should be replaced by era-specific instances that provide real implementations, preventing future accidental use of the stub.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  ├─1─► BlockFetch: deliver block B (valid header/body) to victim node
  │       → B is stored in VolatileDB
  │
  ├─2─► PerasCertDiffusion: send PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B), pcSignature = <garbage> }
  │       → processCerts calls validatePerasCert mkPerasParams cert
  │       → validatePerasCert always returns Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
  │       → certificate added to PerasCertDB via addPerasCertAsync
  │
  └─3─► chainSelSync processes ChainSelAddPerasCert:
          → VolatileDB.getBlockComponent returns header of B
          → chainSelectionForBlock triggered with B's header + full Peras weight boost
          → node may switch to attacker's fork containing B
```

The stub at `SupportsPeras.hs:353–358` is the single necessary vulnerable step; without it, step 2 would throw `PerasCertValidationError` and disconnect the peer.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```
