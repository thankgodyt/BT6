### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Any unprivileged peer connected via the `PerasCertDiffusion` miniprotocol can send a crafted `PerasCert` with an arbitrary round number and boosted-block pointer. The certificate passes "validation" immediately, is written to the `PerasCertDB`, and triggers chain selection — potentially causing the node to switch to a non-canonical fork that the attacker's certificate artificially boosts.

---

### Finding Description

**Root cause — stub validator always returns `Right`:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides the following implementation:

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

Every certificate, regardless of content, is wrapped in `Right` and returned as a `ValidatedPerasCert`. No signature, round-number range, boosted-block existence, or quorum check is performed.

**Inbound path — peer-supplied certs reach the stub without any prior gate:**

`makePerasCertPoolWriterFromChainDB` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` wires this stub directly as the validation callback:

```haskell
(validatePerasCert mkPerasParams)
```

`processCerts` (same file, lines 156–185) calls `validateCert` on every cert not already in the DB. Because the stub always returns `Right`, the `partitionEithers` branch `([], validatedCerts)` is always taken, and every cert is forwarded to `ChainDB.addPerasCertAsync`.

This writer is installed as the live production handler in `ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
```

**Chain-selection consequence:**

`chainSelSync` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs` handles `ChainSelAddPerasCert`. After the cert is stored, it checks whether the boosted block is on the current chain or in the volatile DB. If the boosted block is on a competing fork, chain selection runs and may switch the node to that fork because the Peras boost increases the fork's weight.

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer can craft a `PerasCert` that:
- Names any `PerasRoundNo` (including future rounds)
- Points `pcCertBoostedBlock` at any block in the node's volatile DB — including a block on a competing, non-canonical fork

Because `validatePerasCert` never rejects, the cert is stored and chain selection re-runs with the artificial boost. If the boosted fork is otherwise equal in length to the honest chain, the Peras weight tips the balance, causing the node to irreversibly switch to the attacker-chosen fork. This constitutes a consensus safety failure: an honest node accepts and extends a non-canonical chain driven entirely by a forged, unvalidated certificate from an unprivileged peer.

---

### Likelihood Explanation

**Likelihood: High.**

- The `PerasCertDiffusion` miniprotocol is an open node-to-node protocol; any peer that completes the handshake can send `PerasCert` messages.
- No authentication of the sender is required beyond establishing a TCP connection.
- The attacker needs only to know a block hash present in the target node's volatile DB (obtainable via `ChainSync`) and craft a CBOR-encoded `PerasCert` pointing to it.
- The stub is the **only** `BlockSupportsPeras` instance in the production codebase for the generic `blk` type; there is no fallback real validator.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the certificate's aggregate BLS signature against the committee's public keys for the claimed round.
2. Checks that the boosted block exists and is within the valid depth window.
3. Verifies that the signers collectively hold sufficient stake to meet the Peras quorum threshold.

Until the real validator is ready, the `PerasCertDiffusion` inbound handler should be disabled or should reject all inbound certificates rather than silently accepting them.

---

### Proof of Concept

1. Attacker connects to a target node and runs `ChainSync` to learn a block hash `H` on a competing fork `F` that is currently in the node's volatile DB.
2. Attacker encodes a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint s H }` in CBOR.
3. Attacker sends this cert via the `PerasCertDiffusion` miniprotocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
5. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` stores the cert and re-runs chain selection; fork `F` now carries the Peras boost weight.
7. If `F` is otherwise equal to or longer than the honest chain, the node switches to `F`.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
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
```
