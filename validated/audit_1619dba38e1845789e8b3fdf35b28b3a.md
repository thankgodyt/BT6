### Title
Peras Certificate Signature Verification Bypass Allows Unprivileged Peer to Inject Arbitrary Certificates and Corrupt Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production implementation of `validatePerasCert` in `Block/SupportsPeras.hs` is a stub that unconditionally accepts every inbound certificate without performing any cryptographic or structural validation. Any unprivileged peer reachable via the ObjectDiffusion mini-protocol can send a crafted `PerasCert` for an arbitrary round number boosting an arbitrary block. The certificate passes validation, is stored in the `PerasCertDB`, and triggers chain selection, potentially causing the honest node to prefer a non-canonical fork. This is the direct analog of H-03: instead of replaying a valid signed message (no nonce), the attacker bypasses signature verification entirely (no check at all), achieving the same class of unauthorized state change through a crafted protocol message.

### Finding Description

**Root cause — unconditional acceptance in `validatePerasCert`:**

The `BlockSupportsPeras` instance for all blocks (lines 350–358 of `Block/SupportsPeras.hs`) implements `validatePerasCert` as:

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

Every certificate, regardless of content or origin, is wrapped in `Right` and assigned the full `perasWeight`. No quorum proof, no aggregate BLS signature, no committee membership check, no round-number bounds check is performed.

**Attacker-controlled entry path:**

The ObjectDiffusion inbound handler calls `processCerts` (lines 164–185 of `PerasCert.hs`):

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

`validateCert` is bound to `validatePerasCert mkPerasParams` (line 103 and line 126 of `PerasCert.hs`). Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces an empty error list, and every cert in the batch is forwarded to `addCert`.

**Chain selection consequence:**

`addCert` in the production path is `void . ChainDB.addPerasCertAsync chainDB` (line 132 of `PerasCert.hs`), which enqueues a `ChainSelAddPerasCert` event. `chainSelSync` (lines 483–535 of `ChainSel.hs`) then:
1. Adds the cert to `PerasCertDB` (atomic, deduplicates by round number only).
2. Looks up the boosted block in `VolatileDB`.
3. Calls `chainSelectionForBlock` for the boosted block, potentially switching the node's preferred chain.

The deduplication in `implAddCert` (line 178 of `PerasCertDB/Impl.hs`) only prevents the same **round number** from being stored twice; it does not prevent a fresh crafted cert for a previously unseen round from being accepted.

**Exploit flow:**

1. Attacker connects to an honest node via the ObjectDiffusion mini-protocol (no credentials required).
2. Attacker sends a batch containing a `PerasCert { pcCertRound = R, pcCertBoostedBlock = attackerForkTip }` for a round `R` not yet in the node's `PerasCertDB`.
3. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
4. The cert is stored in `PerasCertDB` with `vpcCertBoost = perasWeight params`.
5. `chainSelSync` triggers chain selection for `attackerForkTip`; if the attacker's fork plus the injected boost outweighs the honest chain, the node switches.
6. The attacker can repeat for successive round numbers (each is a fresh round ID, so deduplication does not block them), continuously boosting the same fork.

### Impact Explanation

An unprivileged peer can make an honest node accept fabricated Peras certificates for arbitrary rounds, each granting `perasWeight` boost to an attacker-chosen block. By injecting enough certificates the attacker can cause the node to permanently prefer a non-canonical fork, breaking chain-selection safety. This is a **Critical** bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-selection manipulation without any stake, key material, or privileged access.

### Likelihood Explanation

The ObjectDiffusion mini-protocol is designed to be reachable by any connected peer. The attacker needs only a TCP connection to the node and knowledge of the wire format for `PerasCert` (which is CBOR-serialised with a public schema). No cryptographic material, no stake, and no operator interaction is required. The stub is present in the current production source tree and is exercised by the live inbound certificate processing path.

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that verifies:
- The aggregate BLS signature over the certificate covers the claimed round number and boosted block.
- The signing keys belong to a quorum of eligible committee members for that round (using the epoch nonce and committee selection data).
- The round number is within the acceptable window relative to the current tip.

Until real validation is in place, the ObjectDiffusion inbound handler for Peras certificates should not be exposed to untrusted peers in any deployment that uses Peras chain-selection weights.

### Proof of Concept

```
Attacker peer → ObjectDiffusion inbound handler
  → processCerts [PerasCert { pcCertRound = 42, pcCertBoostedBlock = <attacker fork tip> }]
    → validatePerasCert mkPerasParams cert
      = Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
    → addCert (WithArrivalTime now validatedCert)
      → ChainDB.addPerasCertAsync chainDB cert
        → chainSelSync: PerasCertDB.addCert → AddedPerasCertToDB
        → chainSelectionForBlock cdb ... attackerForkTip
          → node switches to attacker's fork if boost tips the scale

Repeat for rounds 43, 44, … to continuously re-boost the same fork.
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
