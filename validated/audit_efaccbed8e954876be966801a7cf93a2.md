### Title
Peras Certificate Validation Is a No-Op Stub, Allowing Any Peer to Inject Arbitrary Chain-Selection Boosts — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function — the sole gate that decides whether a `PerasCert` received from a remote peer is legitimate — is an unconditional stub that always returns `Right` and assigns the hardcoded default `perasWeight` boost to every certificate it sees. The production diffusion path (`makePerasCertPoolWriterFromChainDB`) calls this stub with a hardcoded `mkPerasParams` rather than the actual chain configuration. An unprivileged peer can therefore inject a certificate boosting any block it chooses; the node will accept it, store it in the `PerasCertDB`, and immediately re-run chain selection with the artificial weight advantage, potentially switching to a chain the attacker controls.

---

### Finding Description

**Root cause — stub validation:**

`validatePerasCert` in the universal `BlockSupportsPeras` instance is explicitly marked TODO and performs zero cryptographic or semantic checks:

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

Every `PerasCert` — regardless of its round number, boosted block, or any cryptographic content — is unconditionally wrapped in a `ValidatedPerasCert` and returned as `Right`.

**Root cause — hardcoded parameters in the production diffusion path:**

`makePerasCertPoolWriterFromChainDB`, the function wired into the live Peras certificate mini-protocol, calls the stub with the compile-time default `mkPerasParams` instead of the actual node configuration:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

This is the analog of the auction "fee" bug: a critical parameter (`perasWeight`, the chain-selection boost magnitude) is taken from a mutable, operator-replaceable default rather than from the immutable chain state, and the validation gate that should enforce it is absent entirely.

**How the certificate reaches chain selection:**

`processCerts` filters only for duplicate round numbers, then calls `validateCert` (the stub) on every new certificate. All pass. Each is timestamped and forwarded to `addCert`: [3](#0-2) 

`ChainDB.addPerasCertAsync` then calls `chainSelSync` → `chainSelectionForBlock` for the boosted block: [4](#0-3) 

The `PerasWeightSnapshot` used during chain selection is built directly from the `vpcCertBoost` stored in the `PerasCertDB`: [5](#0-4) 

The `totalWeightOfFragment` function adds this boost to the fragment's block count, so a boosted candidate can overtake the current selection: [6](#0-5) 

---

### Impact Explanation

**Impact class:** Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.

An unprivileged peer that can open a connection to a Peras-enabled node can:

1. Craft a `PerasCert` naming any block hash as `pcCertBoostedBlock`.
2. Send it via the Peras certificate object-diffusion mini-protocol.
3. The node accepts it unconditionally, stores it, and re-runs chain selection.
4. The attacker's chosen block receives a weight boost of `perasWeight mkPerasParams` (currently 15) on top of its chain length.
5. If the attacker's candidate chain plus the artificial boost exceeds the current selection's weight, the node switches chains — accepting a potentially adversarial fork.

Because `SecurityParam` k = 2160 and `perasWeight` = 15, a single injected certificate can tip chain selection in favour of a fork that is up to 15 "weight units" shorter than the honest chain. Multiple injected certificates (one per round, since the DB deduplicates by round number) compound this effect.

---

### Likelihood Explanation

Peras is not enabled on mainnet by default (`eraPerasRoundLength = HardFork.NoPerasEnabled`), so the attack surface is currently limited to private testnets and nodes that opt in. However, the production code path (`makePerasCertPoolWriterFromChainDB`) is already wired up and the stub is in a non-test, non-generated production module. Any node operator who enables Peras is immediately exposed. No keys, stake, or special privileges are required — only a TCP connection.

---

### Recommendation

1. **Implement real cryptographic verification** in `validatePerasCert` before Peras is enabled on any network. At minimum, verify the certificate's aggregate BLS/KES signature against the claimed voting committee and confirm the quorum threshold is met.
2. **Derive `PerasCfg` from the actual chain configuration** rather than the hardcoded `mkPerasParams` in `makePerasCertPoolWriterFromChainDB`. The `perasWeight` used to assign boosts must match the on-chain protocol parameters so that parameter changes (analogous to the auction fee) cannot be silently bypassed.
3. **Enforce the `perasWeight` invariant at acceptance time**: a `ValidatedPerasCert` whose `vpcCertBoost` does not equal the current `perasWeight` from the ledger state should be rejected, preventing stale or manipulated boost values from persisting across parameter updates.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  1. Connect to a Peras-enabled node via the Peras cert mini-protocol
  │
  │  2. Send PerasCert { pcCertRound = <fresh round>,
  │                      pcCertBoostedBlock = <tip of attacker's fork> }
  │
  ▼
makePerasCertPoolWriterFromChainDB
  └─ processCerts ... (validatePerasCert mkPerasParams) ...
       └─ validatePerasCert: always Right, boost = 15   ← stub, no checks
            └─ ChainDB.addPerasCertAsync cert
                 └─ chainSelSync (ChainSelAddPerasCert cert)
                      └─ chainSelectionForBlock cdb ... boostedHdr ...
                           └─ totalWeightOfFragment (length + 15) > currentWeight?
                                └─ YES → node switches to attacker's fork
```

The attacker controls `pcCertBoostedBlock` freely. The node performs no signature check, no quorum check, and no stake check before accepting the certificate and re-running chain selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L1-31)
```haskell
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

-- | Data structure for tracking the weight of blocks due to Peras boosts.
module Ouroboros.Consensus.Peras.Weight
  ( -- * 'PerasWeightSnapshot' type
    PerasWeightSnapshot

    -- * Construction
  , emptyPerasWeightSnapshot
  , mkPerasWeightSnapshot

    -- * Conversion
  , perasWeightSnapshotToList

    -- * Insertion
  , addToPerasWeightSnapshot

    -- * Pruning
  , prunePerasWeightSnapshot

    -- * Query
  , isEmptyPerasWeightSnapshot
  , weightBoostOfPoint
  , weightBoostOfFragment
  , totalWeightOfFragment
  , takeVolatileSuffix
  ) where
```
