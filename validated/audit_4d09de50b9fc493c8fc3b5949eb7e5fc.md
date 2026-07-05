### Title
Stub `validatePerasCert` Accepts All Peer-Supplied Peras Certificates Unconditionally, Enabling Chain-Selection Manipulation via First-Write-Wins Round Slot Squatting - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. Combined with the `PerasCertDB`'s first-write-wins semantics (one certificate per `PerasRoundNo`), an unprivileged peer can inject a crafted certificate for any round, have it accepted and stored, cause chain selection to be triggered for an attacker-chosen block, and permanently block any legitimate certificate for that round from influencing chain selection.

---

### Finding Description

**Root cause — stub certificate validation:**

The `BlockSupportsPeras` instance for all blocks contains a `validatePerasCert` that is explicitly marked as a TODO and unconditionally returns `Right`:

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

This stub is the validator called in the live network inbound path. In `makePerasCertPoolWriterFromChainDB`, the `opwAddObjects` handler calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

**Root cause — first-write-wins round slot squatting:**

`processCerts` filters out certs whose `PerasRoundNo` is already in the DB, then validates and adds the rest. The `PerasCertDB` stores exactly one certificate per round number:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  ...
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [3](#0-2) 

Inside `implAddCert`, the DB enforces one-cert-per-round: if `roundNo` is already in `pcdsCertIds`, the new cert is silently dropped as `PerasCertAlreadyInDB`:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
  else do
    ...
    pure AddedPerasCertToDB
``` [4](#0-3) 

**Attacker-controlled entry path:**

The Peras cert diffusion mini-protocol is wired directly to `makePerasCertPoolWriterFromChainDB` in the node-to-node handler:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

Any peer that speaks the Peras cert diffusion protocol can send a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. Because `validatePerasCert` is a stub, the cert passes validation unconditionally, is stored in the `PerasCertDB`, and then `chainSelSync` triggers chain selection for the attacker-chosen boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

---

### Impact Explanation

**Certificate verification bypass (Critical):** Any unprivileged peer can inject a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block in the VolatileDB. Because `validatePerasCert` returns `Right` unconditionally, the cert is accepted as `ValidatedPerasCert` without any signature, quorum, or eligibility check. This directly satisfies the "Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance" criterion.

**Chain selection manipulation via slot squatting (High):** Once the crafted cert is stored for round `R`, any legitimate cert for round `R` is permanently silenced (`PerasCertAlreadyInDB`). The attacker-chosen block receives the Peras weight boost, and `chainSelectionForBlock` is invoked for it. If the boosted block is on a fork, the node may switch to a non-canonical chain. This satisfies "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."

---

### Likelihood Explanation

The Peras cert diffusion mini-protocol is an externally reachable, unauthenticated peer-to-peer channel. No stake, keys, or operator access are required. Any peer that connects and speaks the protocol can send a crafted `PerasCert`. The stub is present in the default `BlockSupportsPeras` instance used for all block types, so the vulnerability is active in every configuration that enables Peras cert diffusion.

---

### Recommendation

1. **Immediate:** Replace the stub `validatePerasCert` with a real implementation that verifies the certificate's cryptographic proof of quorum (aggregate signature over the election ID and candidate block, VRF eligibility proofs for each voter, and quorum threshold check). Until this is done, the Peras cert diffusion mini-protocol should not be enabled in production.

2. **Short-term:** Add a guard in `processCerts` that rejects any batch containing a cert for a round that already has a cert in the DB, rather than silently skipping it. This prevents a race where a crafted cert races a legitimate one.

3. **Long-term:** Align the `PerasCertDB` semantics so that a cert for a round can only be stored after it has been verified against the committee context for that round, making the first-write-wins property safe by construction.

---

### Proof of Concept

1. Attacker connects to a victim node and negotiates the Peras cert diffusion mini-protocol.
2. Attacker observes (or guesses) a block hash `H` in the victim's VolatileDB that is on a fork the attacker wants to promote, and the current Peras round number `R`.
3. Attacker sends a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = Point slot H }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. `addPerasCertAsync` enqueues `ChainSelAddPerasCert` in the ChainSel queue.
6. `chainSelSync` stores the cert in `PerasCertDB` (round `R` is now occupied), then calls `chainSelectionForBlock` for block `H`.
7. If block `H` is on a fork that is now heavier than the current chain due to the Peras weight boost, the node switches to that fork.
8. Any subsequent legitimate cert for round `R` is dropped as `PerasCertAlreadyInDB`, so the attacker's cert permanently controls the weight boost for that round.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L178-198)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
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
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```
