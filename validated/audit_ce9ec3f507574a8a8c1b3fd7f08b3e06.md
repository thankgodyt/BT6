### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the `BlockSupportsPeras` instance is a deliberate stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or committee-membership checks. Because this function is the sole gate between an inbound peer-supplied `PerasCert` and the `PerasCertDB` / chain-selection pipeline, any unprivileged peer can inject an arbitrary certificate that boosts any block it chooses. The boosted block then receives extra Peras weight in chain selection, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validator always succeeds**

The `BlockSupportsPeras` instance for all `StandardHash blk` types provides the following implementation:

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

No signature is verified, no committee membership is checked, no round-number bounds are enforced, and no boosted-block existence is confirmed. Every certificate is unconditionally promoted to `ValidatedPerasCert`.

**Attacker-controlled entry path**

The production pool writer for the Peras certificate object-diffusion miniprotocol calls `validatePerasCert mkPerasParams` as its sole validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` filters out round numbers already in the DB, then calls `validateCert` on each remaining certificate. Because `validatePerasCert` always returns `Right`, every new-round certificate passes: [3](#0-2) 

**Chain-selection consequence**

Once a certificate is added to the `PerasCertDB`, `chainSelSync` in `ChainSel.hs` triggers `chainSelectionForBlock` for the boosted block, giving it the Peras weight boost: [4](#0-3) 

The `PerasCertDB` also exposes a `getWeightSnapshot` used during chain comparison. A fake certificate for a block on a minority fork therefore causes the node to assign that fork extra weight, potentially switching away from the canonical chain.

**Analog to the original report**

The original bug: `setClientOwner` lacks a check that the target address is already associated with a name, so an "unrequired" client can overwrite a "required" client's identity and strip its privilege.

The analog here: `validatePerasCert` lacks all checks (signature, committee membership, round validity), so an unprivileged peer can inject a certificate that grants any block the "required" Peras weight boost — stripping the canonical chain of its privileged selection status.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` claiming to boost any block on any fork. Because the certificate passes validation unconditionally, the node stores it and re-runs chain selection with the fake boost applied. If the boosted block is on a minority or adversarial fork, the node may switch to that fork, constituting a chain-selection manipulation. This maps to the **High** impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The Peras certificate object-diffusion miniprotocol is a public, peer-facing interface. Any connected peer can send a `PerasCert` message. No stake, key material, or operator access is required. The only natural barrier is the per-round deduplication check (`Set.member roundNo alreadyInDb`), which only prevents a second certificate for the same round — it does not prevent the first fake certificate for any new round from being accepted. Likelihood is **High** once the Peras miniprotocol is active on a production node.

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify the aggregate BLS signature against the claimed committee members, confirm each voter is a legitimate committee member for the claimed round, and check that the boosted block point is plausible (e.g., not in the far future or past the immutable tip). The `WFALS` and `EveryoneVotes` committee implementations in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs` already contain the correct `implVerifyCert` logic that should be wired in.

2. **Remove the stub instance** (`instance StandardHash blk => BlockSupportsPeras blk`) or gate it behind a compile-time flag so it cannot be used in production builds.

3. **Add a unit test** that sends a certificate with an invalid signature and asserts it is rejected — analogous to the recommendation in the original report.

---

### Proof of Concept

**Setup**: A private testnet with Peras enabled. Attacker controls one peer connected to an honest node.

**Steps**:

1. Attacker observes that the honest node's current chain tip is block `B_honest` at height `H`.
2. Attacker constructs a minority fork ending at block `B_adv` (height `H` or `H-1`) that the honest node has in its VolatileDB.
3. Attacker crafts a `PerasCert { pcCertRound = R, pcCertBoostedBlock = point B_adv }` with arbitrary (invalid) content.
4. Attacker sends this certificate via the Peras object-diffusion miniprotocol.
5. `processCerts` calls `validatePerasCert mkPerasParams` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
6. Certificate is stored in `PerasCertDB`; `chainSelSync` calls `chainSelectionForBlock` for `B_adv`.
7. Chain selection now compares `B_honest` (no boost) against `B_adv` (with Peras boost weight). If the boost is sufficient, the node switches to the adversarial fork.

**Expected outcome without the fix**: The honest node adopts the adversarial chain.
**Expected outcome with the fix**: The certificate is rejected at step 5 with a signature/committee-membership error, and chain selection is not triggered. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
