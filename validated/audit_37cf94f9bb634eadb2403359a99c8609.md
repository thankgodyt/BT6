### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Forge a Peras Certificate and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally accepts every inbound `PerasCert` without performing any cryptographic, quorum, or eligibility check. Because the Peras certificate diffusion miniprotocol is live and wired directly to `ChainDB.addPerasCertAsync`, any unprivileged peer can send a single crafted certificate that boosts an arbitrary block by `perasWeight = 15` units and trigger chain selection, potentially causing an honest node to switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must verify an inbound certificate before it is stored and used for chain selection. The degenerate instance that covers all block types (marked `-- TODO: degenerate instance for all blks to get things to compile`) implements this gate as an unconditional pass-through:

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

No aggregate signature is verified, no quorum stake threshold is checked, no VRF eligibility is confirmed, and no round-number bounds are enforced. [1](#0-0) 

This instance is the **only** production instance; it is selected for every `StandardHash blk`: [2](#0-1) 

The inbound certificate pool writer for the ChainDB passes this stub directly as the validator:

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

`processCerts` calls `validateCert` on every inbound cert; because the stub always returns `Right`, every cert passes and is forwarded to `addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. `chainSelSync` then adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block, applying the full `perasWeight = 15` boost to chain selection: [5](#0-4) 

The `perasWeight` default is 15 blocks: [6](#0-5) 

The node-to-node handler wires the cert diffusion miniprotocol directly to `makePerasCertPoolWriterFromChainDB`, making this reachable from any connected peer: [7](#0-6) 

---

### Impact Explanation

**Analog to the multi-sig report:** In the multi-sig wallet, n−p+1 colluding owners (fewer than the required quorum p) can force an arbitrary transaction. Here, the quorum threshold (`perasQuorumStakeThreshold = 3/4`) is the analog of p, and the required aggregate signature is the analog of the p required owner signatures. The stub `validatePerasCert` reduces the required quorum from 3/4 of total stake to **zero** — a single peer with no stake at all can forge a certificate.

A crafted `PerasCert` that names any block already present in the VolatileDB will cause the node to re-run chain selection with that block boosted by 15 weight units. A fork that is up to 15 blocks shorter than the canonical chain will be preferred if it carries a forged certificate. This is a **chain selection bug** that lets an unprivileged peer make an honest node prefer a non-canonical chain, directly matching the "High" impact scope: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is active in the production node-to-node handler. Any peer that can establish a connection can send a `PerasCert` message. The only practical constraint is that the boosted block must already be in the node's VolatileDB, which is easily satisfied by an attacker who also diffuses the target block first. No key material, stake, or privileged access is required.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:
1. Verifies the aggregate BLS/KES signature over the certificate body against the declared committee members' verification keys.
2. Checks that the total stake of the signers meets or exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin` (i.e., calls `stakeAboveThreshold` with a properly normalized `PerasVoteStake`).
3. Validates that the certificate's round number is within the accepted window.
4. Validates VRF eligibility proofs for each declared committee member.

Until the real implementation is ready, the stub should at minimum **reject all inbound certificates** (return `Left PerasValidationErr`) rather than accept them unconditionally, so that the diffusion path is inert rather than exploitable.

The normalization issue in `stakeAboveThreshold` (comparing potentially absolute `PerasVoteStake` against a relative threshold) must also be resolved before the real validator is deployed: [8](#0-7) 

---

### Proof of Concept

On a private testnet running the Peras-enabled node:

1. Connect a malicious peer to an honest node via the node-to-node protocol.
2. Diffuse a valid block `B` to the honest node so it lands in the VolatileDB.
3. Send a crafted `PerasCert { pcCertRound = r, pcCertBoostedBlock = point(B) }` via the `PerasCertDiffusion` miniprotocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCertBoost = 15 })` with no checks.
5. `addPerasCertAsync` enqueues `ChainSelAddPerasCert`; `chainSelSync` adds the cert and calls `chainSelectionForBlock` for `B`.
6. Block `B`'s effective chain weight increases by 15. If the canonical chain is within 15 blocks of `B`'s fork, the honest node switches to the adversarial fork.
7. Repeat with a new round number to re-boost after each honest chain extension.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
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
