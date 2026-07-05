### Title
Unconditional Peras Certificate Acceptance Bypasses Cryptographic Validation, Enabling Attacker-Controlled Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the catch-all `BlockSupportsPeras` instance unconditionally returns `Right` (valid) for every certificate it receives, performing zero cryptographic or semantic checks. An unprivileged peer can craft a `PerasCert` that boosts any block on any fork, send it over the Peras certificate mini-protocol, and cause an honest node to treat that fork as having higher total weight than the canonical chain, triggering a chain switch.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must accept or reject incoming Peras certificates before they are stored and used to influence chain selection. The production catch-all instance (the only instance in the codebase) is:

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

This stub skips all of the following checks that a correct implementation must perform:
- BLS aggregate signature verification over `(roundNo, boostedBlock)`
- Per-voter VRF eligibility proof verification (for non-persistent seats)
- Quorum threshold check (sufficient stake-weighted voters)
- Voter set membership against the epoch's stake distribution

The network-facing ingest path in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then accepts every certificate that passes this no-op check and forwards it to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` is documented to trigger a fork switch if the boosted fork becomes heavier: [4](#0-3) 

Inside `chainSelSync`, the accepted certificate is stored in `PerasCertDB` and then `chainSelectionForBlock` is called for the boosted block: [5](#0-4) 

`chainSelectionForBlock` reads the `PerasWeightSnapshot` (which now includes the attacker's boost) and uses it to compare candidate chains: [6](#0-5) 

Chain comparison uses `wsvTotalWeight = blockNo + weightBoost`, so a crafted certificate granting `perasWeight` boost to a shorter fork can make it appear heavier than the honest canonical chain: [7](#0-6) 

`implGetWeightSnapshot` in `PerasCertDB.Impl` builds the snapshot directly from all stored certificates with no re-validation: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer sends a single crafted `PerasCert` that names any block on a minority fork as the boosted block. Because `validatePerasCert` always returns `Right`, the certificate is stored and the `PerasWeightSnapshot` is updated. Chain selection then computes the minority fork's total weight as `blockNo + perasWeight`, which can exceed the canonical chain's `blockNo` alone. The honest node executes `switchTo`, rolling back up to `k` blocks and adopting the attacker's fork as its new selection.

This is a **High** impact chain-selection bug: an unprivileged peer with no stake and no cryptographic keys can make an honest node prefer a non-canonical chain, violating the Peras settlement guarantee and potentially enabling double-spend or ledger-state divergence.

---

### Likelihood Explanation

**Medium.** The Peras certificate mini-protocol is a standard node-to-node protocol reachable by any peer. The attacker needs only to:
1. Construct a `PerasCert` struct with an arbitrary `pcCertRound`, a `pcBoostedBlock` pointing to a block on a minority fork, and any placeholder `pcVoters`/`pcSignature` fields (since they are never checked).
2. Send it over the wire to a target node.

No key material, stake, or prior chain access is required. The only constraint is that the boosted block must already be in the target node's VolatileDB (i.e., the attacker must have previously propagated that block). This is a realistic precondition in any network with competing forks.

---

### Recommendation

Replace the stub `validatePerasCert` with a complete implementation that:
1. Verifies the BLS aggregate signature against the aggregated public keys of the claimed voters.
2. Verifies each non-persistent voter's VRF eligibility proof.
3. Checks that the aggregate stake of the voters meets the quorum threshold from `PerasParams`.
4. Validates voter set membership against the epoch's stake distribution.

Until the full implementation is in place, the node should refuse to accept externally received `PerasCert` objects (i.e., treat all inbound certs as invalid) rather than accepting them unconditionally.

---

### Proof of Concept

**Setup:** A private testnet with two nodes, A (honest) and B (attacker). Both have received blocks up to slot 100 on the canonical chain. A minority fork diverges at slot 90 with a block `B_fork` at slot 95.

**Steps:**

1. Attacker node B propagates `B_fork` to node A via the standard BlockFetch protocol. Node A stores it in its VolatileDB but does not switch (canonical chain is heavier).

2. Attacker constructs a crafted `PerasCert`:
   ```
   PerasCert
     { pcCertRound    = 42          -- any round not yet in A's DB
     , pcBoostedBlock = point(B_fork)
     , pcVoters       = <empty or garbage>
     , pcSignature    = <zero bytes>
     }
   ```

3. Attacker sends this cert to node A via the Peras certificate object-diffusion mini-protocol.

4. Node A's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })` unconditionally. [9](#0-8) 

5. The cert is stored in `PerasCertDB`. `implGetWeightSnapshot` now returns a snapshot with `point(B_fork) → perasWeight`. [10](#0-9) 

6. `chainSelSync` calls `chainSelectionForBlock` for `B_fork`. Chain selection computes:
   - Canonical chain weight: `blockNo(100)` = 100
   - Fork weight: `blockNo(95) + perasWeight` = 95 + W

   If `W > 5` (which is the default `perasWeight`), the fork is preferred.

7. Node A executes `switchTo`, rolling back 10 blocks and adopting the attacker's fork. [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-634)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-198)
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
