### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Selection Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines a `validatePerasCert` method as the mandatory gate for accepting inbound Peras certificates. The sole production instance of this typeclass unconditionally returns `Right` for every certificate, performing no cryptographic or semantic checks. Because the production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`) calls this stub as its validator, any unprivileged peer can inject arbitrary `PerasCert` objects that are accepted, stored in `PerasCertDB`, and used to boost blocks during chain selection — without any proof of quorum, committee membership, or BLS signature validity.

---

### Finding Description

**Root cause — the validation mechanism exists but its implementation is a permanent no-op stub:**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the required validation gate:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only production instance, explicitly marked as a temporary placeholder, implements this as:

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

This unconditionally returns `Right` for every certificate, regardless of content. [1](#0-0) 

**The stub is wired directly into the production inbound-certificate path:**

`makePerasCertPoolWriterFromChainDB` — the writer used by the live Peras certificate diffusion mini-protocol — passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass (which they always do), adds them to the database: [3](#0-2) 

**Accepted certificates directly influence chain selection:**

`chainSelSync` processes each accepted certificate: if the boosted block is present in the VolatileDB, it immediately triggers `chainSelectionForBlock` with the certificate's boost weight applied: [4](#0-3) 

The boost weight is drawn from `getWeightSnapshot` on the `PerasCertDB`, which now contains the attacker-injected certificate.

**The mini-protocol handler is wired in production diffusion:**

`hPerasCertDiffusionClient` in `NodeToNode.hs` calls `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB`, making this reachable from any peer connection: [5](#0-4) 

---

### Impact Explanation

**Impact: High — chain-selection manipulation by an unprivileged peer.**

An attacker peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block hash in the victim node's VolatileDB. Because `validatePerasCert` never rejects anything, the certificate is accepted, stored, and its boost weight is applied during chain selection. This can cause the honest node to prefer a non-canonical fork that has been artificially boosted by fake certificates, violating the Peras chain-selection invariant that only certificates backed by a genuine quorum of committee members should influence fork choice.

This maps to the allowed scope: **"High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."**

---

### Likelihood Explanation

**Likelihood: High.**

- The attack requires only a standard peer connection via the Peras certificate diffusion mini-protocol, which is open to any node-to-node peer.
- No keys, stake, or privileged access are required.
- The attacker only needs to know (or guess) a block hash present in the victim's VolatileDB — trivially obtained by observing the chain.
- The stub is the only instance in the codebase and is used unconditionally in production diffusion setup.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that checks:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` is valid against the claimed committee members' keys.
2. The claimed voters constitute a genuine quorum (sufficient stake weight) according to the current committee selection.
3. Each voter's eligibility proof (VRF for non-persistent members) is valid.

Until real validation is implemented, the Peras certificate diffusion mini-protocol should not be enabled in production builds, or inbound certificates should be rejected entirely rather than accepted unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to victim node as a peer; the `hPerasCertDiffusionClient` handler is activated.
2. Attacker sends a `PerasCert` message with `pcCertRound = R` and `pcCertBoostedBlock = <hash of a block on a minority fork>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always returns `Right ValidatedPerasCert{...}`.
4. `ChainDB.addPerasCertAsync chainDB cert` is called; `chainSelSync` processes `ChainSelAddPerasCert`.
5. The boosted block is found in the VolatileDB; `chainSelectionForBlock` is triggered with the fake certificate's boost weight.
6. Chain selection now considers the minority fork as having a Peras certificate boost, potentially switching the node's selected chain to the attacker-favored fork.

**Key code references:**

- Stub always-`Right` implementation: [6](#0-5) 
- Production inbound pipeline using the stub: [7](#0-6) 
- Chain selection triggered by accepted certificate: [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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
