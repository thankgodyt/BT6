### Title
Stub `validatePerasCert` Always Accepts Peer-Supplied Peras Certificates, Enabling Unauthorized Chain-Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate, performing no cryptographic or structural validation. Because the `PerasCertDiffusion` miniprotocol is wired into the node-to-node stack and feeds directly into `addPerasCertAsync` → chain selection, any unprivileged peer can inject arbitrary `PerasCert` objects that boost any block point with any weight, manipulating the `PerasWeightSnapshot` used by `preferAnchoredCandidate` and potentially forcing a chain switch to a non-canonical fork.

---

### Finding Description

**Analog mapping.** The `PermissionRegistry` bug allows the contract owner to set permissions for *other users* — a privileged write that bypasses the "only modify your own state" invariant. The analog here is that *any peer* can write Peras weight boosts for *any block* (not just blocks they legitimately certified), because the certificate validation gate is a no-op stub.

**Root cause — `validatePerasCert` stub.** [1](#0-0) 

The catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` (line 320) applies to every block type, including `CardanoBlock`. Its `validatePerasCert` implementation (lines 350–358) is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

It never inspects the certificate's content, never verifies committee membership, never checks BLS/aggregate signatures, and never validates the round number or boosted block point. Every certificate is accepted.

**Inbound path — `processCerts`.** [2](#0-1) 

`processCerts` is the handler for certificates arriving from peers. It calls the injected `validateCert` function (which is `validatePerasCert mkPerasParams` in production) and, if all certificates pass, adds them to the database. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every peer-supplied certificate is stored.

**Production wiring — `makePerasCertPoolWriterFromChainDB`.** [3](#0-2) 

This is the production pool writer. It passes `validatePerasCert mkPerasParams` as the validator and `ChainDB.addPerasCertAsync chainDB` as the sink. The `addPerasCertAsync` call enqueues a `ChainSelAddPerasCert` message that triggers chain selection.

**Miniprotocol registration.** [4](#0-3) 

`aPerasCertDiffusionClient` and `aPerasCertDiffusionServer` are registered as node-to-node miniprotocol handlers, making the inbound certificate path reachable from any peer.

**Chain selection impact — `preferAnchoredCandidate`.** [5](#0-4) 

`preferAnchoredCandidate` branches on `isEmptyPerasWeightSnapshot weights`. Once a peer injects even one certificate, the snapshot becomes non-empty and the Peras weighted comparison path is activated for all subsequent chain selection decisions. The attacker-controlled `PerasWeightSnapshot` is then used to compare candidate chains against the current selection.

**`implAddCert` — no secondary validation.** [6](#0-5) 

The `implAddCert` function (with its own TODO comment at line 167) stores the certificate directly into `pcdbState` without any additional checks, updating the fingerprint and `pcdsLatestCertSeen` — the latter directly affecting voting eligibility.

---

### Impact Explanation

An unprivileged peer can:

1. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = pt }` where `pt` is the tip of any fork in the VolatileDB.
2. Send it via the `PerasCertDiffusion` miniprotocol.
3. The receiving node accepts it unconditionally, adds it to `PerasCertDB`, and triggers `chainSelSync` → `ChainSelAddPerasCert`.
4. The `PerasWeightSnapshot` now contains attacker-chosen weights for attacker-chosen blocks.
5. `preferAnchoredCandidate` uses these weights; a fork that was previously not preferred may now be preferred, causing the node to switch chains.

This is a **chain selection manipulation** — an unprivileged peer can make an honest node prefer a non-canonical or adversarially-chosen chain, violating the chain selection invariant that only legitimately certified blocks receive weight boosts.

Additionally, `pcdsLatestCertSeen` is updated, which is described as "a precondition for voting in any round except for the very first one." An attacker can therefore also manipulate the node's voting eligibility state.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is registered in the node-to-node stack and is reachable from any peer without authentication. The attack requires only the ability to connect as a peer and send a well-formed (but content-arbitrary) `PerasCert` CBOR message. No keys, stake, or privileged access are needed. The stub is the catch-all instance for all block types, so it applies in every deployment configuration.

---

### Recommendation

1. **Remove or gate the stub.** The catch-all `instance StandardHash blk => BlockSupportsPeras blk` must not be reachable in production. Either remove it entirely and require explicit instances, or gate the `PerasCertDiffusion` miniprotocol behind a feature flag that is disabled until real validation is implemented.

2. **Implement `validatePerasCert` properly.** The real implementation must verify committee membership, aggregate BLS signatures, round number bounds, and that the boosted block point exists and is within the volatile window.

3. **Resolve the TODO in `implAddCert`.** The `PerasCertDB.addCert` path should also enforce invariants (e.g., one certificate per round, valid boost bounds) as a defense-in-depth measure.

4. **Disable the miniprotocol until validation is complete.** Until `validatePerasCert` performs real cryptographic checks, the `PerasCertDiffusion` inbound handler should reject all certificates.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer connects via node-to-node PerasCertDiffusion miniprotocol
  → objectDiffusionInboundPeerPipelined (NodeToNode.hs:1020)
  → makePerasCertPoolWriterFromChainDB.opwAddObjects (PerasCert.hs:121-133)
  → processCerts ... (validatePerasCert mkPerasParams) ... (PerasCert.hs:164-173)
  → validatePerasCert params cert = Right ValidatedPerasCert{...}  ← always succeeds
  → ChainDB.addPerasCertAsync chainDB cert
  → ChainSelAddPerasCert enqueued
  → chainSelSync cdb (ChainSelAddPerasCert cert varProcessed)  (ChainSel.hs:483)
  → PerasCertDB.addCert cdbPerasCertDB cert  (ChainSel.hs:495)
  → PerasWeightSnapshot updated with attacker-chosen (block point, weight)
  → preferAnchoredCandidate uses non-empty snapshot → Peras weighted path
  → chain switch to attacker-boosted fork if its weighted view exceeds current chain
```

**Crafted certificate (CBOR-serialisable):**

```haskell
PerasCert
  { pcCertRound      = PerasRoundNo 1          -- any round not yet in DB
  , pcCertBoostedBlock = BlockPoint slot hash  -- tip of any fork in VolatileDB
  }
```

This certificate passes `validatePerasCert` unconditionally, is stored in `PerasCertDB`, and its boost is reflected in the `PerasWeightSnapshot` used by all subsequent chain selection comparisons.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1000-1043)
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

  aPerasCertDiffusionServer ::
    NodeToNodeVersion ->
    ResponderContext addrNTN ->
    Channel m bPCD ->
    m ((), Maybe bPCD)
  aPerasCertDiffusionServer
    version
    ResponderContext{rcConnectionId = them}
    channel = do
      labelThisThread "PerasCertDiffusionServer"
      runPeerWithLimits
        (TraceLabelPeer them `contramap` tPerasCertDiffusionTracer)
        (cPerasCertDiffusionCodec (mkCodecs version))
        blPerasCertDiffusion
        timeLimitsObjectDiffusion
        channel
        ( objectDiffusionOutboundPeer
            (hPerasCertDiffusionServer version them)
        )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
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
