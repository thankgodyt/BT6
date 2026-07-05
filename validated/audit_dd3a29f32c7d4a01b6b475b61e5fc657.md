### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain-Selection Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate it receives. Any unprivileged peer can therefore send a crafted `PerasCert` over the Peras certificate diffusion mini-protocol, have it accepted without any cryptographic or quorum check, and have it stored in `PerasCertDB`. The stored certificate then inflates the `PerasWeightSnapshot` used by chain selection, allowing the attacker to artificially boost the weight of an adversarial chain fragment and cause an honest node to prefer it over the canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The degenerate `instance StandardHash blk => BlockSupportsPeras blk` always returns `Right`, accepting every certificate regardless of its cryptographic content, round number plausibility, or quorum evidence.

**Entry path — network-received certificates are validated only by this stub:**

`processCerts` in the Peras certificate object-pool writer calls `validatePerasCert mkPerasParams` directly: [2](#0-1) 

Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` use this stub validator with a hardcoded `mkPerasParams`, explicitly marked `-- TODO replace when actual plumbing is in place`.

**Storage — accepted certificates are stored without further checks:**

`implAddCert` performs only a round-number deduplication check; it contains no cryptographic or structural validation: [3](#0-2) 

**Chain selection — the stored certificates directly drive weight comparison:**

`implGetWeightSnapshot` builds the `PerasWeightSnapshot` from every certificate in `pcdsCertsByTicket`, including attacker-injected ones: [4](#0-3) 

`weightedSelectView` then uses this snapshot to compute `wsvWeightBoost` and `wsvTotalWeight`, which drives `preferCandidate` in chain selection: [5](#0-4) 

The `PerasWeightSnapshot` is also used by `takeVolatileSuffix` to determine the immutability boundary (what counts as "buried under weight k"), so inflating it can also cause the node to treat more blocks as immutable than it should: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can inject an arbitrary number of `PerasCert` objects, each claiming to boost any block point on an adversarial chain fragment. Because `validatePerasCert` always returns `Right`, every such certificate is accepted, timestamped, and stored. The resulting `PerasWeightSnapshot` assigns arbitrarily large `wsvWeightBoost` to the adversarial fragment. When `preferCandidate` compares `wsvTotalWeight` of the honest chain against the adversarial chain, the inflated weight causes the node to switch to the adversarial chain. This is a **chain-selection safety failure**: an honest node is made to prefer a non-canonical, potentially adversary-controlled chain, violating the Common Prefix property.

Additionally, because `takeVolatileSuffix` uses the same inflated snapshot to determine the rollback boundary, the node may prematurely treat adversarial blocks as immutable, making recovery impossible without manual intervention.

---

### Likelihood Explanation

The attack requires only network access to a node running the Peras certificate diffusion mini-protocol. No stake, keys, or operator access are needed. The attacker sends a batch of crafted `PerasCert` messages; `processCerts` filters only by round-number deduplication (one certificate per round), so the attacker can cover many rounds by sending one certificate per round. The code path is unconditional and exercised on every inbound certificate batch.

---

### Recommendation

1. **Replace the stub `validatePerasCert`** with a real implementation that verifies the aggregate BLS signature over the vote set, checks that the quorum threshold is met using the correct stake distribution from the ledger, and confirms the boosted block point exists on a valid chain. The BLS infrastructure is already present in `Ouroboros.Consensus.Peras.Crypto.BLS`.

2. **Pass the ledger-derived stake distribution** into `validatePerasCert` rather than using a hardcoded `mkPerasParams`, so that committee membership and quorum thresholds are checked against the actual epoch snapshot.

3. **Enforce equivocation rejection in `implAddCert`**: the state-machine test already documents the invariant (same round must boost the same block), but the production `implAddCert` does not enforce it.

4. **Track the referenced issue** `https://github.com/tweag/cardano-peras/issues/120` to completion before enabling Peras certificate diffusion on any network where chain-selection weight is security-critical.

---

### Proof of Concept

```
1. Attacker connects to a node via the Peras certificate object-diffusion mini-protocol.

2. Attacker constructs N crafted PerasCert values, one per round number,
   each with pcCertBoostedBlock pointing to a block on the attacker's
   adversarial chain fragment F_adv:

     cert_i = PerasCert { pcCertRound = i, pcCertBoostedBlock = blockPoint F_adv[i] }

3. Attacker sends the batch to the node.

4. processCerts calls validatePerasCert mkPerasParams on each cert.
   validatePerasCert unconditionally returns:
     Right (ValidatedPerasCert { vpcCert = cert_i, vpcCertBoost = perasWeight mkPerasParams })

5. Each cert is stored in PerasCertDB via implAddCert (round-number
   deduplication passes because each cert uses a distinct round number).

6. getWeightSnapshot returns a PerasWeightSnapshot mapping every block
   on F_adv to a large PerasWeight.

7. When the node receives headers for F_adv, weightedSelectView computes:
     wsvTotalWeight(F_adv) = blockNo(F_adv.tip) + N * perasWeight
   which exceeds wsvTotalWeight of the honest chain.

8. preferCandidate returns ShouldSwitch, and the node adopts F_adv.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
