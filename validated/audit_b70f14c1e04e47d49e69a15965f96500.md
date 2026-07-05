### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or semantic checks. Because this stub is wired directly into the live node-to-node certificate diffusion path, any unprivileged peer can inject arbitrarily crafted Peras certificates. Those certificates are stored in the `PerasCertDB` / `ChainDB` and immediately influence chain selection by assigning Peras weight boosts to attacker-chosen blocks, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation that always succeeds**

The `BlockSupportsPeras` type-class instance that covers all block types is explicitly labelled a "degenerate instance … to get things to compile":

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
```

No BLS aggregate-signature check, no committee-membership check, no round-number bounds check, and no boosted-block existence check is performed. Every certificate, regardless of content, is wrapped in `ValidatedPerasCert` and returned as valid.

**Production wiring — the stub is the live handler**

`makePerasCertPoolWriterFromChainDB` is the writer used by the actual node-to-node protocol handler (`hPerasCertDiffusionClient`):

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
```

`processCerts` calls `validateCert` on every inbound certificate; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`. That async action triggers chain-selection re-evaluation with the new certificate's weight boost applied.

**Attacker-controlled entry path**

```
Malicious peer
  → ObjectDiffusion mini-protocol (hPerasCertDiffusionClient, NodeToNode.hs:382)
  → makePerasCertPoolWriterFromChainDB (PerasCert.hs:118)
  → processCerts (PerasCert.hs:164)
  → validatePerasCert mkPerasParams  ← always Right (SupportsPeras.hs:353)
  → ChainDB.addPerasCertAsync        ← cert stored, chain-sel triggered
  → PerasWeightSnapshot updated      ← attacker-chosen block gets boost
  → chain selection re-run           ← node may switch to attacker's fork
```

**Analogy to the external report**

The external report describes an order that claims to hold a specific NFT as collateral but accepts any NFT from the same collection because the type check is absent. Here, the system claims to hold a *validated* Peras certificate but accepts any certificate from any peer because the cryptographic and semantic checks are absent. In both cases the "type" label (`ValidatedPerasCert` / `OrderType NFT`) is applied without the checks that give it meaning.

---

### Impact Explanation

A malicious peer can craft a `PerasCert` with:
- `pcCertRound` set to any round number not yet in the database (bypassing the deduplication filter in `processCerts`), and
- `pcCertBoostedBlock` pointing to any block on a competing fork.

The certificate is stored and its weight boost is reflected in `PerasWeightSnapshot`. Chain selection then re-evaluates all candidate chains using the inflated weight, and the node may irreversibly switch to the attacker's fork. Because the certificate is persisted in the `PerasCertDB`, the incorrect weight boost survives node restarts.

**Impact category (High):** Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The attack requires only a standard peer connection; no keys, stake, or privileged access are needed. The attacker simply sends a well-formed CBOR-encoded `PerasCert` over the `ObjectDiffusion` mini-protocol. The stub validation provides zero resistance. Likelihood is **High** for any deployment where the Peras diffusion mini-protocol is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the BLS aggregate signature over `(pcRoundNo, pcBoostedBlock)` using the committee's aggregate verification key.
2. Checks that every voter seat index in `pcVoters` is a legitimate committee member for the given round.
3. Confirms that `pcCertRound` falls within the valid window relative to the current chain tip.
4. Confirms that `pcBoostedBlock` refers to a block that actually exists and is reachable from the current chain.

Until the real implementation is in place, the `hPerasCertDiffusionClient` handler should either be disabled or should reject all inbound certificates rather than accepting them unconditionally.

---

### Proof of Concept

1. Attacker connects to an honest node as a normal peer.
2. Attacker identifies a competing fork tip `B_fork` that it wants the victim to adopt.
3. Attacker sends a single `PerasCert` message: `{ pcRoundNo = <any unseen round>, pcBoostedBlock = B_fork, pcVoters = <any non-empty voter map>, pcSignature = <any bytes> }`.
4. `processCerts` checks only that `pcRoundNo` is not already in the DB — it is not, so the cert passes.
5. `validatePerasCert mkPerasParams` returns `Right ValidatedPerasCert{..}` unconditionally.
6. `ChainDB.addPerasCertAsync` stores the cert; `PerasWeightSnapshot` is updated to give `B_fork` a Peras weight boost equal to `perasWeight params`.
7. Chain selection re-runs; if the boosted weight of the fork exceeds the canonical chain's weight, the node switches forks.
8. The node is now on the attacker's non-canonical chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
