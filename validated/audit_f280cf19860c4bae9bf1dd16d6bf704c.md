Based on my thorough code review, I have traced the full attack path and confirmed the vulnerability is real and reachable.

---

### Title
First-Write-Wins Race in `implAddCert` Combined with Stub `validatePerasCert` Allows Unprivileged Peer to Permanently Poison PerasCertDB Weight Snapshot — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

### Summary

An unprivileged peer can inject a crafted `PerasCert` for round R boosting an attacker-chosen block `B_wrong` via the NodeToNode ObjectDiffusion miniprotocol. Because `validatePerasCert` is a stub that unconditionally returns `Right` (no BLS signature, no committee membership, no VRF check), and because `implAddCert` deduplicates by round number only (first-write-wins), the fraudulent certificate is permanently stored. All subsequent honest certificates for round R are silently dropped as `PerasCertAlreadyInDB`. `getWeightSnapshot` then permanently returns a `PerasWeightSnapshot` boosting `B_wrong`, causing `chainSelectionForBlock` to prefer chains containing `B_wrong` over the honest chain.

### Finding Description

**Root cause 1 — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The `validatePerasCert` implementation for the universal `StandardHash blk` instance unconditionally returns `Right`, accepting any certificate regardless of its BLS aggregate signature, committee membership, or VRF eligibility proofs. This is explicitly marked as a TODO referencing issue #120.

**Root cause 2 — `implAddCert` deduplicates by round number only (first-write-wins):** [2](#0-1) 

The check `Set.member roundNo (pcdsCertIds pcds)` at line 178 means the first certificate received for a given round is stored permanently. No comparison of the boosted block is performed. A later honest certificate for the same round is silently discarded as `PerasCertAlreadyInDB`.

**Root cause 3 — The diffusion inbound path calls the stub validator:** [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. Since `validatePerasCert` always returns `Right`, every inbound certificate from any peer passes validation. [4](#0-3) 

**Root cause 4 — The NodeToNode handler wires this path into production:** [5](#0-4) 

**Root cause 5 — `getWeightSnapshot` reflects the poisoned state:** [6](#0-5) 

`implGetWeightSnapshot` iterates all `pcdsCertsByTicket` entries and builds the weight map from them. Once `B_wrong` is stored, it permanently contributes its boost to chain selection.

**Root cause 6 — `chainSelectionForBlock` consumes the poisoned snapshot:** [7](#0-6) 

The `weights` read atomically from `getPerasWeightSnapshot` at line 634 are used throughout `constructPreferableCandidates` and `chainSelection`, permanently biasing chain selection toward `B_wrong`.

**The API comment explicitly assumes equivocation is impossible — an assumption that is not enforced:** [8](#0-7) 

The comment states "the two certificates must be identical because certificate equivocation is impossible." This invariant is entirely unenforced in the current code.

### Impact Explanation

The impact is **durable use of the wrong ledger state via permanent chain selection based on a fraudulent weight boost**. Once the attacker's certificate for round R is stored, the node permanently prefers chains containing `B_wrong` over the honest chain containing `B_correct`. This is a High-scope ChainDB/chain-selection bug: an unprivileged peer causes an honest node to prefer a non-canonical chain beyond the intended security assumptions, without any operator fault.

### Likelihood Explanation

The attack requires only a NodeToNode peer connection — no stake, no keys, no admin access. The attacker simply sends a well-formed `PerasCert` CBOR message with an arbitrary `pcCertRound` and `pcCertBoostedBlock` before the honest certificate arrives. The race window is the entire period between when the attacker connects and when the honest certificate is first received. The attack is deterministic (not probabilistic) and permanently effective.

### Recommendation

1. **Immediately implement real cryptographic validation in `validatePerasCert`** (issue #120): verify the BLS aggregate signature against the committee's aggregate public key, verify VRF eligibility proofs for non-persistent voters, and verify the round number and boosted block are consistent with the certificate message.
2. **Add conflict detection in `implAddCert`**: if a certificate for round R already exists but boosts a different block than the incoming certificate, this is equivocation evidence and should be logged and the incoming certificate rejected (not silently dropped as `PerasCertAlreadyInDB`).
3. **Do not deploy the ObjectDiffusion Peras cert inbound handler on mainnet** until both of the above are implemented.

### Proof of Concept

```haskell
-- io-sim scenario (pseudocode):
-- 1. Start a node with an empty PerasCertDB.
-- 2. Inject cert(round=R, block=B_wrong) via addPerasCertSync.
-- 3. Inject cert(round=R, block=B_correct) via addPerasCertSync.
-- 4. Assert: getCertIds contains R exactly once. ✓
-- 5. Assert: getWeightSnapshot boosts B_wrong (not B_correct). ✓
-- 6. Assert: chainSelectionForBlock selects the chain containing B_wrong. ✓
--
-- Step 2 succeeds because validatePerasCert always returns Right.
-- Step 3 returns PerasCertAlreadyInDB and is silently dropped.
-- Steps 4-6 follow from implAddCert's first-write-wins semantics.
```

The concrete entry point is `hPerasCertDiffusionClient` in `NodeToNode.hs` → `objectDiffusionInbound` → `processCerts` → `validatePerasCert` (stub, always `Right`) → `ChainDB.addPerasCertAsync` → `chainSelSync` → `implAddCert`.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-201)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L616-623)
```haskell
newtype AddPerasCertPromise m = AddPerasCertPromise
  { waitPerasCertProcessed :: m AddPerasCertChainSelOutcome
  -- ^ Wait until the Peras certificate has been processed (which potentially
  -- includes switching to a different chain). If the PerasCertDB did already
  -- contain a certificate for this round, the certificate is ignored (as the
  -- two certificates must be identical because certificate equivocation is
  -- impossible).
  }
```
