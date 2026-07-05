### Title
`validatePerasCert` Unconditionally Returns `Right` — Any Peer Can Inject Arbitrary Peras Certificates to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as a function that **always returns `Right` (success)** without performing any cryptographic or committee-membership checks. Because this is the validator wired into the production `ObjectPoolWriter` for the Peras certificate diffusion miniprotocol, any unprivileged peer can send a crafted `PerasCert` with an arbitrary boosted-block pointer, have it accepted unconditionally, stored in the `PerasCertDB`, and applied as a chain-selection weight boost — potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase — it is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` that covers every block type. [2](#0-1) 

**Production wiring — the no-op validator is used in both pool writers:**

`makePerasCertPoolWriterFromChainDB` (the production path) passes `validatePerasCert mkPerasParams` directly as the certificate validator to `processCerts`: [3](#0-2) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass, stores them via `addCert`: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every inbound certificate is stored unconditionally.

**Inbound path — any peer can trigger this:**

The `objectDiffusionInbound` handler calls `opwAddObjects` (which resolves to `processCerts`) on every batch of objects received from a remote peer: [5](#0-4) 

No peer authentication or privilege check precedes this call.

**Chain-selection impact — stored certs become weight boosts:**

`implAddCert` stores the `ValidatedPerasCert` (with its `vpcCertBoost`) in the `PerasCertDB`: [6](#0-5) 

`implGetWeightSnapshot` then exposes these stored certs as a `PerasWeightSnapshot`, which is consumed by chain selection as the `weights` parameter in `ChainSelEnv`: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `pcCertBoostedBlock` (including a block on an adversarial fork) and any `pcCertRound`. Because `validatePerasCert` never rejects anything, the certificate is stored and its `perasWeight` boost is applied during chain selection. This allows the attacker to:

1. **Boost a non-canonical chain** — inject a certificate pointing to a block on an adversarial fork, causing the victim node to prefer that fork over the honest chain. This is a **chain-selection safety failure** matching the "High: chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact category.
2. **Suppress a legitimate boost** — since only one certificate per round is stored (deduplication by `pcCertRound`), an attacker who races ahead of the honest committee can occupy a round slot with a fake certificate, preventing the legitimate certificate from being stored and denying the honest chain its boost.

---

### Likelihood Explanation

- The attacker needs only a standard peer connection to the victim node — no keys, no stake, no privileged access.
- The `PerasCert` type is serialisable and its fields (`pcCertRound`, `pcCertBoostedBlock`) are fully attacker-controlled.
- The ObjectDiffusion miniprotocol is a standard network-facing protocol; any connected peer can send certificate batches.
- The degenerate instance is the **only** instance and is unconditionally used in production writers.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS signature over the election ID and candidate block using the declared voters' verification keys.
2. That each declared voter is a registered committee member with positive stake in the relevant epoch.
3. That the total stake of the signers meets the quorum threshold.

Until the real implementation is ready, the production `ObjectPoolWriter` should refuse all inbound certificates (return a hard error or drop them) rather than accept them unconditionally. The `TODO` comment referencing issue `#120` should be treated as a security-blocking item, not a deferred enhancement.

---

### Proof of Concept

1. Connect to a victim node's Peras certificate diffusion miniprotocol endpoint.
2. Craft a `PerasCert` with:
   - `pcCertRound = R` (any round not yet in the victim's DB)
   - `pcCertBoostedBlock = <hash of attacker's fork tip>`
3. Send the certificate via `MsgReplyObjects` in the ObjectDiffusion protocol.
4. The victim's `objectDiffusionInbound` handler calls `opwAddObjects [cert]`.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}`.
6. The certificate is stored in `PerasCertDB` via `ChainDB.addPerasCertAsync`.
7. On the next chain selection event, `getWeightSnapshot` returns a snapshot that includes the attacker's boost for the adversarial fork tip.
8. `preferAnchoredCandidate` now weighs the adversarial chain higher, and the victim node switches to the attacker's fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L408-411)
```haskell
        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1083-1101)
```haskell
mkChainSelEnv CDB{..} blockCache weights curChain punish =
  ChainSelEnv
    { lgrDB = cdbLedgerDB
    , bcfg = configBlock cdbTopLevelConfig
    , varInvalid = cdbInvalid
    , varTentativeState = cdbTentativeState
    , varTentativeHeader = cdbTentativeHeader
    , getTentativeFollowers =
        filter ((TentativeChain ==) . fhChainType) . Map.elems
          <$> readTVar cdbFollowers
    , blockCache
    , weights
    , curChain
    , validationTracer =
        TraceAddBlockEvent . AddBlockValidation >$< cdbTracer
    , pipeliningTracer =
        TraceAddBlockEvent . PipeliningEvent >$< cdbTracer
    , punish
    }
```
