### Title
Missing Peras Certificate Validation Allows Unprivileged Peer to Inject Arbitrary Chain-Selection Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the `BlockSupportsPeras` instance is a stub that unconditionally accepts every inbound certificate without performing any cryptographic or committee-membership check. An unprivileged peer can send a crafted `PerasCert` that is stored in the `PerasCertDB`, artificially inflates the `PerasWeightSnapshot` for an arbitrary block, and causes honest nodes to prefer a non-canonical fork over the honest chain.

---

### Finding Description

`validatePerasCert` in the degenerate `BlockSupportsPeras` instance always returns `Right`, assigning the full configured boost weight to any certificate regardless of its content:

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

This function is the sole validation gate in `processCerts`, the inbound handler for certificates received from peers over the object-diffusion mini-protocol:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate not already in the DB; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which calls `implAddCert` to persist it in `PerasCertDB`: [4](#0-3) 

`implAddCert` stores the certificate in `pcdsCertsByTicket` without any further validation: [5](#0-4) 

`implGetWeightSnapshot` then materialises a `PerasWeightSnapshot` from every stored certificate, including the crafted one: [6](#0-5) 

`chainSelectionForBlock` reads this snapshot and passes it to `constructPreferableCandidates` and `preferAnchoredCandidate`: [7](#0-6) 

`preferAnchoredCandidate` uses `weightedSelectView` on the suffix of each candidate fragment; when the snapshot is non-empty (Peras active), the total weight drives the fork-choice decision: [8](#0-7) 

**Analog to the original bug.** In `LT.vy`, `set_staker()` updates the staker address without transferring the old staker's balance, so the new staker starts with zero balance and all downstream calculations are wrong. Here, `validatePerasCert` "sets" a new certificate without transferring the required validation proof — the certificate is accepted with a full, unearned boost weight, and all downstream chain-selection calculations are wrong.

---

### Impact Explanation

When Peras is enabled, chain selection is driven by `wsvTotalWeight = blockNo + weightBoost`. A crafted certificate that boosts a block on an adversarial fork by `perasWeight` (the full configured boost) can make that fork appear heavier than the honest chain, causing the node to switch to the adversarial fork. This is a **chain-selection manipulation** that lets an unprivileged peer make an honest node permanently prefer a non-canonical chain, violating the Common Prefix property.

Additionally, `pcdsLatestCertSeen` (used as a voting precondition — "having seen a certificate is a precondition for voting in any round except the very first") can be set to a crafted certificate, corrupting the node's voting behaviour. [9](#0-8) 

**Impact class:** High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The entry path is direct and requires no special privilege: any peer connected via the Peras object-diffusion mini-protocol can send a `PerasCert` message. The `processCerts` handler is the first and only validation point, and it unconditionally accepts every certificate. The condition for triggering the bug is simply that Peras is enabled (`isEmptyPerasWeightSnapshot` returns `False` once the first certificate is stored).

---

### Recommendation

1. Implement real cryptographic validation inside `validatePerasCert`: verify committee membership, aggregate BLS/KES signatures, and confirm the certificate round number is within the valid window.
2. Until real validation is in place, gate the entire `processCerts` path behind a Peras-enabled feature flag so that no certificate can be accepted when the validation logic is a stub.
3. Add an invariant check in `implAddCert` that rejects any certificate whose `ValidatedPerasCert` was produced by the stub instance.

---

### Proof of Concept

1. Connect to a node with Peras enabled via the object-diffusion mini-protocol.
2. Craft a `PerasCert { pcCertRound = R, pcCertBoostedBlock = <tip of adversarial fork> }`.
3. Send the certificate to the node. `processCerts` calls `validatePerasCert mkPerasParams` → always `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
4. `chainSelSync` stores the certificate in `PerasCertDB` via `implAddCert`.
5. `implGetWeightSnapshot` returns a `PerasWeightSnapshot` with a full boost on the adversarial fork's tip.
6. The next call to `chainSelectionForBlock` (triggered either by the certificate itself at line 531, or by the next block arrival) computes `weightedSelectView` for the adversarial suffix; its `wsvTotalWeight` now exceeds the honest chain's weight.
7. `preferAnchoredCandidate` returns `ShouldSwitch`; the node switches to the adversarial fork. [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L494-502)
```haskell
    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L144-149)
```haskell
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-72)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
  -- (at origin).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
