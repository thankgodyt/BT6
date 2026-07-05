### Title
Peras Certificate Verification Bypass via Stub `validatePerasCert` Allows Arbitrary Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines a `validatePerasCert` method intended to enforce all certificate validity checks before a peer-supplied Peras certificate is accepted. The concrete production instance is a stub that unconditionally returns `Right` for every certificate, bypassing all validation. Because the certificate diffusion inbound path calls this stub directly, any unprivileged peer can inject a crafted `PerasCert` with an arbitrary round number and block point. The certificate is stored in the `PerasCertDB` and immediately used to boost a block's chain weight, which can trigger a fork switch away from the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` class declares:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The sole concrete instance (used for all blocks) is:

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

This stub accepts every certificate unconditionally. The certificate diffusion inbound handler wires this directly into the production node-to-node protocol:

```haskell
(makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `(validatePerasCert mkPerasParams)` as the validator: [3](#0-2) 

`processCerts` filters out already-known round numbers, then calls `validateCert` on each remaining certificate. Because `validateCert` is the stub, every new certificate passes and is forwarded to `addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` is documented to trigger a fork switch if the boosted block becomes heavier than the current selection: [5](#0-4) 

The `PerasCertDB` stores the certificate and updates the `PerasWeightSnapshot`, which is used by chain selection to compare candidate chains: [6](#0-5) 

The analog to the external report is exact: the intended restriction path (`isPerasVotingAllowed` with VR-1A/VR-1B/VR-2A/VR-2B rules, plus cryptographic certificate verification) is fully defined but never called during certificate ingestion. The actual inbound path calls only the stub, which is the "unguarded" bypass route. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with:
- Any `pcCertRound` (e.g., a future round, a round during a cooldown period, or a round that never reached quorum)
- Any `pcCertBoostedBlock` (e.g., a block on a minority fork)

The certificate is accepted, stored, and its `perasWeight` boost is applied to the targeted block. If the boosted block is on a fork, chain selection may switch to that fork, causing the honest node to abandon the canonical chain. This constitutes an unauthorized chain-selection manipulation reachable from any peer connection, matching the **High** impact category: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is active in the production node-to-node handler. Any connected peer can send a `PerasCert` message. No authentication, stake proof, quorum proof, or round-validity check is performed. The attack requires only knowledge of the wire format (which is public) and a valid peer connection.

---

### Recommendation

Replace the stub `validatePerasCert` instance with a real implementation that enforces:
1. The certificate's round number is within the valid window (not in cooldown, not stale beyond `perasCertMaxRounds`).
2. The certificate contains a valid quorum of cryptographically verified votes from eligible committee members.
3. The boosted block is a known, valid block on a plausible chain.

Until the real implementation is ready, the inbound certificate diffusion handler should reject all certificates (analogous to how the vote diffusion handler currently uses `PerasVoteStakeDistr mempty` to reject all votes). [8](#0-7) 

---

### Proof of Concept

1. Attacker connects to an honest node via the node-to-node protocol and negotiates the `PerasCertDiffusion` mini-protocol.
2. Attacker sends a `PerasCert` with `pcCertRound = N` (any round not yet in the node's `PerasCertDB`) and `pcCertBoostedBlock = <point on attacker's preferred fork>`.
3. `processCerts` filters out already-known rounds — this cert is new, so it proceeds.
4. `validatePerasCert mkPerasParams cert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = 15 })` unconditionally.
5. `addPerasCertAsync` stores the certificate and triggers chain selection.
6. Chain selection computes the Peras weight of the attacker's fork as `base_weight + 15` (the `perasWeight` boost), potentially making it heavier than the honest chain.
7. The honest node switches to the attacker's fork. [1](#0-0) [9](#0-8)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L78-86)
```haskell
isPerasVotingAllowed ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  PerasVotingRulesDecision
isPerasVotingAllowed pvv =
  evalPred (perasVotingRules pvv) $ \e ->
    case e of
      ETrue{} -> Vote e
      EFalse{} -> NoVote e
```
