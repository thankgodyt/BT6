### Title
Unconditional `validatePerasCert` Stub Combined with Round-Indexed First-Come-First-Served `PerasCertDB` Allows Unprivileged Peer to Inject Fake Peras Certificate and Corrupt Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate ingest path accepts any certificate from an unprivileged peer without performing any cryptographic or quorum verification (`validatePerasCert` unconditionally returns `Right`). The `PerasCertDB` stores at most one certificate per Peras round number on a strict first-come-first-served basis. A malicious peer that sends a crafted `PerasCert` for round R first permanently occupies that round slot, causing the legitimate certificate for round R to be silently dropped as `PerasCertAlreadyInDB`. The adversarial certificate then influences chain selection via `getWeightSnapshot`, giving a Peras weight boost to an attacker-chosen block and causing honest nodes to prefer a non-canonical chain.

---

### Finding Description

**Step 1 — Unconditional certificate validation bypass**

The `BlockSupportsPeras` instance used throughout the production code path implements `validatePerasCert` as an unconditional stub:

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

No aggregate BLS signature is checked, no quorum threshold is verified, and no committee membership is validated. Every `PerasCert` received from any peer passes validation unconditionally. [1](#0-0) 

**Step 2 — Production ingest path uses the stub**

`makePerasCertPoolWriterFromChainDB` is the production network-facing writer. It calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` filters out already-known round numbers, then calls `validateCert` on the remainder. Because `validateCert` always returns `Right`, every new-round certificate from any peer is accepted and forwarded to `addCert`. [3](#0-2) 

**Step 3 — First-come-first-served round registration in `PerasCertDB`**

`implAddCert` stores the first certificate for a given `PerasRoundNo` and silently drops all subsequent ones:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
  else do
    ...
    pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
```

There is no comparison of the incoming certificate against the stored one (e.g., checking whether the boosted block matches). The round number is the sole key. [4](#0-3) 

**Step 4 — Adversarial certificate influences chain selection**

`chainSelSync` processes inbound `PerasCert` events, adds them to `PerasCertDB`, and triggers chain selection for the boosted block: [5](#0-4) 

`preferAnchoredCandidate` uses `getWeightSnapshot` from `PerasCertDB` to apply Peras weight boosts when comparing candidate chains. An adversarial certificate stored for round R will boost the attacker's chosen block in every subsequent chain selection comparison until garbage-collected. [6](#0-5) 

**Analog to the external report**

| External (AlignedLayer) | This codebase (Ouroboros Peras) |
|---|---|
| `batchesState` keyed by `batchMerkleRoot` only | `pcdsCertIds` keyed by `PerasRoundNo` only |
| No authentication on `createNewTask` | `validatePerasCert` always returns `Right` |
| Front-runner occupies the slot with 1 wei | Attacker sends first cert for round R |
| Legitimate batcher's task permanently blocked | Legitimate cert for round R permanently dropped |
| Malicious `batchDataPointer` in emitted events | Adversarial `pcCertBoostedBlock` influences chain selection weights |

---

### Impact Explanation

An unprivileged peer that wins the race for round R installs an arbitrary `PerasCert` boosting any block of its choice. The honest node's chain selection then applies a Peras weight boost to that adversarial block. If the adversarial block is on a fork, the honest node may switch to the adversarial chain. The legitimate certificate for round R is permanently suppressed for the lifetime of that round in the DB. This constitutes:

- **Bypass of Peras certificate/signature validation** enabling unauthorized certificate acceptance (Critical per scope).
- **Chain selection manipulation** causing an honest node to prefer a non-canonical chain beyond intended security assumptions (High per scope).

---

### Likelihood Explanation

The attack requires only a network connection to the target node and the ability to send a `PerasCert` message before the legitimate certificate arrives — a standard race condition exploitable by any peer. No keys, stake, or privileged access are required. The `validatePerasCert` stub is in the active production code path with no feature flag or guard preventing its use.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras certificate diffusion path is enabled in production. At minimum, verify the aggregate BLS signature against the committee's aggregate verification key and confirm the quorum threshold is met.
2. **Reject equivocating certificates at the DB level**: if a certificate for round R already exists and the incoming certificate boosts a *different* block, treat it as an equivocation and disconnect the peer rather than silently dropping it.
3. **Gate the ingest path** behind a feature flag that is disabled until full validation is implemented, preventing the stub from being reachable on a live network.

---

### Proof of Concept

Private-testnet sequence (no privileged access required):

1. Start an honest node N with Peras enabled.
2. Connect attacker peer A to N.
3. Let the honest network produce block B_honest at slot S in round R.
4. Before the legitimate `PerasCert(round=R, boostedBlock=B_honest)` propagates to N, attacker A sends `PerasCert(round=R, boostedBlock=B_evil)` where `B_evil` is a block on an adversarial fork.
5. N's `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
6. `implAddCert` stores `(round=R, boostedBlock=B_evil)` and sets `pcdsCertIds = {R}`.
7. The legitimate `PerasCert(round=R, boostedBlock=B_honest)` arrives; `implAddCert` returns `PerasCertAlreadyInDB` and discards it.
8. `getWeightSnapshot` now returns a weight boost for `B_evil`.
9. `preferAnchoredCandidate` applies this boost; if the adversarial fork containing `B_evil` is otherwise equal in length to the honest chain, N switches to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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
