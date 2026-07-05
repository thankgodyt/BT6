### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Unauthorized Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance provides a `validatePerasCert` implementation that unconditionally returns `Right` (valid) for every certificate, performing no cryptographic or committee-membership checks. The network-facing Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB` → `processCerts`) calls this stub as its sole validation gate. An unprivileged peer can therefore inject any crafted `PerasCert` — with an arbitrary round number and boosted-block pointer — and the node will accept it, store it in the `PerasCertDB`, and trigger chain selection with the fake certificate's weight boost.

---

### Finding Description

**Root cause — stub validation that always succeeds**

`BlockSupportsPeras` is a type class with a `validatePerasCert` method. The only concrete instance in the codebase is the universal overlapping instance for all `StandardHash blk`:

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

This function ignores every field of `cert` and returns `Right` unconditionally. There is no signature check, no committee-membership check, no round-number plausibility check, and no boosted-block existence check.

**Contrast with block/header validation**

Blocks and headers entering the node via ChainSync are subjected to three mandatory checks before they can influence chain selection: envelope validation (`validateEnvelope`), protocol-specific checks (`updateChainDepState`, which verifies KES and VRF signatures for Praos), and time-based checks. [2](#0-1) 

Peras certificates arriving via the object-diffusion mini-protocol are supposed to go through an analogous gate (`validatePerasCert`) before being stored and acted upon. That gate is a no-op stub.

**Network-facing entry path**

`makePerasCertPoolWriterFromChainDB` is the production writer used when the node receives Peras certificates from peers. It passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on each incoming certificate; if all pass (which they always do), it calls `addCert` for each one. [4](#0-3) 

**Chain-selection consequence**

Once a certificate is accepted into the `PerasCertDB`, `chainSelSync` processes it: it looks up the boosted block in the `VolatileDB` and calls `chainSelectionForBlock` with the certificate's weight boost applied. [5](#0-4) 

A fake certificate pointing to a block on an adversarial fork will cause the node to re-evaluate chain selection with that fork receiving an unearned weight boost, potentially causing the node to switch to the adversarial chain.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` whose `pcCertBoostedBlock` points to any block in the node's `VolatileDB`. Because `validatePerasCert` always returns `Right`, the certificate is stored and chain selection is re-run with the fake boost. This directly enables:

- **Bypass of Peras certificate/vote verification** — unauthorized certificates are accepted without any cryptographic or committee check, satisfying the Critical impact criterion.
- **Chain-selection manipulation** — the fake weight boost can make the node prefer a non-canonical or adversary-controlled fork, satisfying the High impact criterion.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a new, network-reachable surface. Any peer that can establish a connection and speak the protocol can send arbitrary `PerasCert` values. No special privileges, keys, or stake are required. The stub is the **only** implementation of `validatePerasCert` in the repository; there is no fallback or override for production Cardano block types.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with actual validation that checks, at minimum:

1. **Committee membership** — the certificate must be signed/attested by a quorum of legitimate committee members for the claimed round.
2. **Round plausibility** — the round number must be within the acceptable window relative to the current slot.
3. **Boosted-block existence and ancestry** — the boosted block must be a known, valid block on a plausible chain.
4. **Cryptographic signatures** — any signatures embedded in the certificate must be verified against the committee's keys.

Until the real implementation is in place, the stub should at minimum reject all certificates (return `Left PerasValidationErr`) rather than accept all of them, so that the network-facing path is safe by default.

---

### Proof of Concept

1. Attacker connects to a target node and speaks the Peras object-diffusion mini-protocol.
2. Attacker sends a `PerasCert` with:
   - `pcCertRound` set to the current Peras round.
   - `pcCertBoostedBlock` set to the point of a block on an adversarial fork that is present in the target node's `VolatileDB`.
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}` unconditionally. [6](#0-5) 
4. `ChainDB.addPerasCertAsync` enqueues the certificate; `chainSelSync` stores it in `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block. [7](#0-6) 
5. Chain selection now treats the adversarial fork as having an additional `perasWeight` boost; if this tips the balance, the node switches to the adversarial chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs (L501-522)
```haskell
validateHeader ::
  (BlockSupportsProtocol blk, ValidateEnvelope blk) =>
  TopLevelConfig blk ->
  LedgerView (BlockProtocol blk) ->
  Header blk ->
  Ticked (HeaderState blk) ->
  Except (HeaderError blk) (HeaderState blk)
validateHeader cfg ledgerView hdr st = do
  withExcept HeaderEnvelopeError $
    validateEnvelope
      cfg
      ledgerView
      (untickedHeaderStateTip st)
      hdr
  chainDepState' <-
    withExcept HeaderProtocolError $
      updateChainDepState
        (configConsensus cfg)
        (validateView (configBlock cfg) hdr)
        (blockSlot hdr)
        (tickedHeaderStateChainDep st)
  return $ HeaderState (NotOrigin (getAnnTip hdr)) chainDepState'
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L494-532)
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
