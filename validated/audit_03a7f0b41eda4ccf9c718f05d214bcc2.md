### Title
Stub `validatePerasCert` Allows Any Peer to Inject Crafted Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in `BlockSupportsPeras.hs` is a stub that unconditionally returns `Right` for every certificate it receives. This stub is wired directly into the production inbound certificate-diffusion handler (`processCerts` in `PerasCert.hs`). Because no cryptographic or semantic check is performed, any unprivileged peer can craft a `PerasCert` for an arbitrary round and block, have it accepted as `ValidatedPerasCert`, and cause the ChainDB to trigger chain selection for the boosted block — potentially switching the node to a shorter or adversarial fork.

---

### Finding Description

**Root cause — always-valid stub:**

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

This is the only instance of `BlockSupportsPeras` in the codebase (declared as a "degenerate instance for all blks to get things to compile"). No concrete override exists. [2](#0-1) 

**Stub wired into the production inbound handler:**

`makePerasCertPoolWriterFromChainDB` — the production pool writer used by the certificate-diffusion miniprotocol — passes this stub directly to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

**`processCerts` accepts every certificate that passes the stub:**

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) -> throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validateCert` always returns `Right`, `errs` is always empty and every peer-supplied certificate is forwarded to `addCert` (i.e., `ChainDB.addPerasCertAsync`).

**Chain selection is triggered for the boosted block:**

`chainSelSync` for `ChainSelAddPerasCert` adds the certificate to `PerasCertDB`, updates the `PerasWeightSnapshot`, and then calls `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

`chainSelectionForBlock` reads the freshly-updated `PerasWeightSnapshot` (which now includes the attacker-injected boost) and uses it to compare the boosted fork against the current chain:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [6](#0-5) 

`weights` is then passed to `preferAnchoredCandidate` and `compareChainDiffs`, so the artificially boosted fork can win chain selection even if it is shorter than the current chain. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can:

1. Deliver valid (but shorter) blocks for a competing fork via BlockFetch, placing them in the VolatileDB.
2. Send a crafted `PerasCert` that names any block on that fork as the boosted block.
3. Because `validatePerasCert` is a no-op stub, the certificate is accepted unconditionally.
4. The `PerasWeightSnapshot` is updated with the attacker-chosen boost weight.
5. `chainSelectionForBlock` is invoked for the boosted block; the boosted fork now outweighs the honest chain.
6. The node switches to the adversarial fork.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended security assumptions of the Peras weight mechanism.

---

### Likelihood Explanation

The certificate-diffusion miniprotocol is reachable by any connected peer. The attack requires only that the adversary (a) have a valid block already in the victim's VolatileDB (trivially achievable via normal block diffusion) and (b) send a single crafted `PerasCert` message. No key material, stake, or privileged access is needed. The stub is in production code with an open TODO referencing a known issue (`cardano-peras/issues/120`), meaning it is present in any deployment that enables the Peras certificate-diffusion miniprotocol.

---

### Recommendation

Replace the always-`Right` stub with a real implementation of `validatePerasCert` that verifies:
- The aggregate BLS signature over the round number and boosted block hash.
- That the certificate's round number is within the valid window.
- That the claimed voters are eligible committee members for that round.

Until real validation is in place, the certificate-diffusion inbound handler should reject all externally received certificates (e.g., by returning a hard error or disabling the miniprotocol entirely) rather than silently accepting them.

---

### Proof of Concept

```
Attacker peer                          Victim node
     |                                      |
     |-- BlockFetch: deliver blocks B1..Bn  |
     |   (valid fork, shorter than tip)     |
     |                                      |
     |-- CertDiffusion: send PerasCert{     |
     |     round=R, boostedBlock=Bn }       |
     |                                      |
     |                    processCerts()    |
     |                    validatePerasCert → Right (stub)
     |                    addPerasCertAsync(cert)
     |                    chainSelSync(ChainSelAddPerasCert)
     |                      PerasCertDB.addCert → weight updated
     |                      chainSelectionForBlock(Bn)
     |                        preferAnchoredCandidate(weights) → ShouldSwitch
     |                        switchTo(fork containing Bn)
     |                                      |
     |                    Node now on adversarial fork
``` [1](#0-0) [3](#0-2) [4](#0-3) [8](#0-7) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```
