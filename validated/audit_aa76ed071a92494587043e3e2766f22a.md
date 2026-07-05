### Title
Unconditional Peras Certificate Acceptance Bypasses All Vote/Certificate Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every inbound certificate, regardless of committee membership, cryptographic signatures, or quorum. Any unprivileged NTN peer can inject a crafted `PerasCert` that boosts an arbitrary block, causing the receiving node to trigger chain selection with an attacker-controlled weight boost — a direct bypass of Peras certificate/vote verification.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a Peras certificate before it is stored and acted upon. The production instance (the only instance in the codebase, covering all `StandardHash blk`) is:

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

This stub is wired directly into the production inbound certificate pool writer used by the ChainDB:

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
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass, adds them to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer passes.

Once stored, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which calls `chainSelSync` → `chainSelectionForBlock` for the boosted block, applying the `vpcCertBoost` weight to chain selection: [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block in the VolatileDB. The certificate is accepted without any committee membership check, signature verification, or quorum requirement. The receiving node then runs chain selection treating that block as having a Peras weight boost (`vpcCertBoost = perasWeight params`). This allows an attacker to:

1. Boost an adversarial fork block, causing the honest node to prefer the adversarial chain over the canonical chain — a consensus safety failure.
2. Inject certificates for every Peras round, permanently polluting the `PerasCertDB` and corrupting the node's view of which chain has accumulated Peras weight.

This matches the allowed impact scope: **Critical — bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance**, directly analogous to the CCIP report's "no validation of message sender → attacker can mint/unlock arbitrary tokens."

---

### Likelihood Explanation

The attack path requires only a standard NTN connection. The `PerasCertDiffusion` mini-protocol is served to all NTN peers via `aPerasCertDiffusionClient` in `NodeToNode.hs`: [5](#0-4) 

No stake, no keys, and no special privilege are required. Any peer that can establish an NTN connection can send a crafted `PerasCert`. The code is in the production source tree and is wired into the live ChainDB chain-selection path. The TODO comment confirms the validation is intentionally absent, not accidentally omitted.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that checks:

1. **Committee membership**: The certificate must be signed/attested by a quorum of eligible committee members for the claimed round.
2. **Cryptographic signatures**: Each committee member's signature over the `(round, boostedBlock)` tuple must be verified against the registered committee key.
3. **Quorum threshold**: The aggregate stake of signing members must meet the Peras quorum parameter.
4. **Round freshness**: The certificate's round number must be within the acceptable window relative to the current chain tip.

Until real validation is in place, the `PerasCertDiffusion` mini-protocol should not be enabled on production or private-testnet nodes, or inbound certificates should be rejected entirely (`validatePerasCert _ _ = Left PerasValidationErr`).

---

### Proof of Concept

1. Connect to a target node as a standard NTN peer.
2. Via the `PerasCertDiffusion` mini-protocol, advertise a `PerasRoundNo` not yet in the node's `PerasCertDB`.
3. When the node requests the certificate, respond with a crafted `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
5. The certificate is stored via `ChainDB.addPerasCertAsync`.
6. `chainSelSync` triggers `chainSelectionForBlock` for `adversarialBlockPoint` with the Peras weight boost applied, causing the node to re-evaluate chain selection favouring the attacker-chosen block. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1000-1023)
```haskell
  aPerasCertDiffusionClient ::
    NodeToNodeVersion ->
    ExpandedInitiatorContext addrNTN PeerTrustable m ->
    Channel m bPCD ->
    m (NodeToNodeInitiatorResult, Maybe bPCD)
  aPerasCertDiffusionClient
    version
    ExpandedInitiatorContext
      { eicConnectionId = them
      , eicControlMessage = controlMessageSTM
      }
    channel = do
      labelThisThread "PerasCertDiffusionClient"
      ((), trailing) <-
        runPipelinedPeerWithLimits
          (TraceLabelPeer them `contramap` tPerasCertDiffusionTracer)
          (cPerasCertDiffusionCodec (mkCodecs version))
          blPerasCertDiffusion
          timeLimitsObjectDiffusion
          channel
          ( objectDiffusionInboundPeerPipelined
              (hPerasCertDiffusionClient version controlMessageSTM them)
          )
      return (NoInitiatorResult, trailing)
```
