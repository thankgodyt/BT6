### Title
Peras Certificate Verification Bypass: `validatePerasCert` Stub Always Accepts Any Peer-Supplied Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance provides a stub `validatePerasCert` that unconditionally returns `Right` for every certificate, regardless of its content. This stub is the **only** implementation wired into the production Peras certificate diffusion inbound handler. Any unprivileged peer can send a crafted `PerasCert` over the `hPerasCertDiffusionClient` mini-protocol; the certificate will pass "validation" and be stored in the `PerasCertDB`, where it can trigger chain selection and cause the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as a required method. The only instance in the codebase is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` that provides a degenerate implementation:

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

No cryptographic check, no structural check, no issuer identity check — every certificate is accepted as valid.

**Production wiring — `makePerasCertPoolWriterFromChainDB`:**

The production cert-inbound pool writer passes this stub directly as the validation function:

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

**Network entry point — `hPerasCertDiffusionClient`:**

This writer is installed as the inbound handler for every peer connection in `mkHandlers`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [3](#0-2) 

**`processCerts` — the internal function with the wrong validation:**

`processCerts` is the internal function called from both `makePerasCertPoolWriterFromCertDB` (test/isolated path) and `makePerasCertPoolWriterFromChainDB` (production path). In both cases it receives `validatePerasCert mkPerasParams` as its `validateCert` argument. Because that function always returns `Right`, the `partitionEithers` branch that would reject invalid certs is never taken:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [4](#0-3) 

Every cert from every peer always lands in the `([], validatedCerts)` branch and is added to the DB.

**Analog to the external report:**

The external report's bug is: `_transfer()` is called from multiple external entry points (`transfer`, `transferFrom`, `transferTo`) each with a different sender context, but the internal `_burn(msg.sender, _fee)` uses the wrong identity (`msg.sender` instead of the `sender` parameter). Here, `processCerts` is called from multiple external entry points (production ChainDB path and isolated CertDB path) and in both cases the wrong validation function (a stub that ignores the cert's identity/content entirely) is passed, so the wrong entity — any arbitrary certificate — is accepted.

---

### Impact Explanation

Once a crafted `ValidatedPerasCert` is stored in the `PerasCertDB`, it is fed into chain selection via `addPerasCertAsync`. The `PerasWeightSnapshot` used during chain selection assigns a boost (`vpcCertBoost = perasWeight params`) to the block named in `pcCertBoostedBlock`. An attacker who controls a peer can:

1. Craft a `PerasCert` naming any block hash and any round number.
2. Send it over the `hPerasCertDiffusionClient` mini-protocol.
3. The node accepts it unconditionally, stores it, and re-runs chain selection with the artificial boost applied.
4. If the boosted block is on a competing fork, the node may switch to that fork, diverging from the canonical chain.

This is a **bypass of Peras certificate verification** enabling unauthorized certificate acceptance and chain-selection manipulation by an unprivileged peer.

---

### Likelihood Explanation

- The `hPerasCertDiffusionClient` handler is active on every node-to-node connection once the Peras feature flag is enabled.
- No authentication or stake proof is required to send a `PerasCert` message.
- The stub is the **only** `BlockSupportsPeras` instance; there is no override for any concrete block type.
- The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known incomplete implementation that has not yet been replaced with real validation.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over the certificate's `(electionId, candidate)` pair against the declared voter set.
2. Checks that the declared voters collectively hold sufficient stake (above the quorum threshold) as of the relevant epoch's stake snapshot.
3. Verifies that `pcCertRound` and `pcCertBoostedBlock` are consistent with the current chain state.

Until real validation is in place, the `hPerasCertDiffusionClient` handler should either be disabled or should reject all inbound certificates rather than accepting them unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <attacker-chosen block> }
  → hPerasCertDiffusionClient (NodeToNode.hs:375-384)
  → makePerasCertPoolWriterFromChainDB (PerasCert.hs:118-137)
  → processCerts (PerasCert.hs:164-185)
      validateCert = validatePerasCert mkPerasParams
      validatePerasCert _ cert = Right (ValidatedPerasCert cert boost)  ← always Right
      partitionEithers [...] = ([], [ValidatedPerasCert ...])
      addCert (WithArrivalTime now validatedCert)
  → ChainDB.addPerasCertAsync chainDB
  → chain selection re-runs with artificial boost on attacker-chosen block
``` [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-410)
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
      , hPerasCertDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionOutboundTracer tracers))
            (perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasCertPoolReaderFromChainDB $ getChainDB)
            version
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
            version
            controlMessageSTM
```
