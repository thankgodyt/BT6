### Title
Unconditional `validatePerasCert` Acceptance Allows Any Crafted Peras Certificate to Influence Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — it performs zero cryptographic or semantic checks. This function is called on every inbound Peras certificate received from an unprivileged peer via the production certificate diffusion mini-protocol. Any peer can craft a certificate with an arbitrary round number and boosted block hash, have it accepted as "validated," stored in the `PerasCertDB`, and used to trigger chain selection, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate before any certificate is stored or acted upon. The universal instance (the only one in the codebase) implements it as:

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

No signature verification, no quorum check, no round-validity check, no boosted-block existence check — every certificate unconditionally becomes a `ValidatedPerasCert`.

The production inbound path in `NodeToNode.hs` wires this directly to the network:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- always Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` only rejects a batch when `validateCert` returns `Left`; since `validatePerasCert` never does, every certificate passes:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

The accepted certificate is then added to the `PerasCertDB` and asynchronously submitted to chain selection via `ChainDB.addPerasCertAsync`. In `chainSelSync`, the certificate's `pcCertBoostedBlock` is used to look up a block in the `VolatileDB` and trigger `chainSelectionForBlock` for it:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

The analog to the ERC20 `mint` bug is exact: just as `mint` increments `totalSupply` and assigns tokens without checking `_to != address(0)`, `validatePerasCert` stamps a certificate as `ValidatedPerasCert` and the system updates `PerasCertDB` state and triggers chain selection without checking any property of the certificate's content.

---

### Impact Explanation

**Critical — Bypass of Peras certificate verification enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer can send a `PerasCert` with:
- An arbitrary `pcCertRound` (any round number, including future rounds)
- An arbitrary `pcCertBoostedBlock` (any block point, including one on a minority or adversarial fork)

The node will accept it as a `ValidatedPerasCert`, store it in the `PerasCertDB`, and use it to boost the weight of the targeted block in chain selection. Because Peras certificate boosts are designed to make a chain significantly heavier than competing forks, this can cause an honest node to prefer a non-canonical or adversarially-controlled chain over the honest chain, violating chain selection safety.

---

### Likelihood Explanation

**High.** The inbound certificate diffusion handler is active for every connected peer in the production node-to-node stack. No authentication, stake ownership, or key material is required to send a `PerasCert` message. The `validatePerasCert` stub is the only gate, and it unconditionally passes. The `TODO` comment at line 318 explicitly acknowledges this is a degenerate placeholder instance, not a temporary test shortcut. [6](#0-5) 

---

### Recommendation

Implement `validatePerasCert` with the full set of required checks before the certificate is accepted as `ValidatedPerasCert`. At minimum this must include:

1. **Aggregate BLS signature verification** — verify that `pcSignature` is a valid aggregate signature over the election identifier and boosted block hash, using the public keys of the claimed voters.
2. **Quorum check** — verify that the aggregate stake of the signers meets the Peras quorum threshold.
3. **Round validity** — verify that `pcCertRound` corresponds to a valid, non-expired Peras round relative to the current ledger state.
4. **Voter eligibility** — verify that each claimed voter was a legitimate committee member for the given round.

Until this is implemented, the `hPerasCertDiffusionClient` handler should not be wired into the production node-to-node stack, or inbound certificates should be dropped entirely rather than passed through a no-op validator.

---

### Proof of Concept

On a private testnet with Peras diffusion enabled:

1. Connect a malicious peer to an honest node.
2. Craft a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of a block on a minority fork>`.
3. Send it via the `hPerasCertDiffusionClient` object-diffusion mini-protocol.
4. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert ...)` with no error.
5. Observe that `ChainDB.addPerasCertAsync` is called, the certificate is stored in `PerasCertDB`, and `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. If the boosted block is present in the `VolatileDB`, the node will re-evaluate chain selection with the artificial weight boost, potentially switching to the adversarial fork.

The root cause is entirely in the `validatePerasCert` stub at: [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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
