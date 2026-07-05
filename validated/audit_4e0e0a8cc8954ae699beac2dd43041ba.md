### Title
Missing Intra-Batch Duplicate Round-Number Check in `processCerts` Allows Malicious Peer to Inject Arbitrary Peras Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

`processCerts` filters inbound Peras certificates against the set of round numbers **already in the database**, but performs no uniqueness check on round numbers **within the batch itself**. Because `validatePerasCert` is currently a stub that unconditionally accepts every certificate, a malicious peer can send a single batch containing a crafted certificate for round R (boosting a weak or attacker-chosen block) placed before the legitimate certificate for round R. The crafted certificate is accepted first; the legitimate one is silently discarded by the DB. The node's chain-selection weight for that round is permanently set to the attacker's chosen block.

---

### Finding Description

`processCerts` is the inbound processing function for Peras certificates received over the network:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb =
        filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [1](#0-0) 

The deduplication guard `alreadyInDb` is a snapshot of round numbers **already persisted** before the batch arrives. It does not detect two certificates for the same round number appearing within the same batch. Both pass the filter, both are validated, and both are submitted to `addCert` via `mapM_`.

The DB-level `implAddCert` does handle the second arrival atomically:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
  else ...
``` [2](#0-1) 

However, `processCerts` calls `mapM_` and **discards the return value**, so `PerasCertAlreadyInDB` is silently swallowed. The first certificate in the batch for a given round wins unconditionally; the second is dropped without error or disconnection.

The second structural precondition is that `validatePerasCert` is currently a stub that always returns `Right`:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [3](#0-2) 

This stub is wired into both production pool writers:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [4](#0-3) 

The state-machine test model explicitly acknowledges that equivocating certificates (same round, different boosted block) must be rejected, and enforces this as a precondition:

```haskell
-- We should reject equivocating certificates, that is, certificates
-- for the same round but boosting different blocks.
AddCert cert -> all p model.certs
 where
  p cert' =
    getPerasCertRound cert /= getPerasCertRound cert'
      || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
``` [5](#0-4) 

This precondition is enforced only in the test model, not in the production inbound path.

---

### Impact Explanation

Peras certificates carry a boost weight that directly influences chain selection. A certificate for round R boosting block B causes the node to add `vpcCertBoost` weight to B when comparing candidate chains. By injecting a certificate for round R that boosts an attacker-chosen block B′ (not the canonical block), the attacker causes the node to assign extra chain-selection weight to B′. This can make the node prefer a non-canonical or weaker chain over the honest chain, constituting a chain-selection safety failure reachable by an unprivileged peer.

The `getWeightSnapshot` function aggregates boost weights from all stored certificates:

```haskell
mkPerasWeightSnapshot
  [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
  | cert <- Map.elems (pcdsCertsByTicket pcds) ]
``` [6](#0-5) 

Once a certificate for round R is stored, subsequent legitimate certificates for the same round are silently dropped by `implAddCert`. The corruption is durable for the lifetime of the DB.

---

### Likelihood Explanation

High. The attacker-controlled entry path is the Peras certificate diffusion mini-protocol (`objectDiffusionInboundPeerPipelined`), reachable by any peer. The attack requires only sending a single crafted batch. With the current stub `validatePerasCert`, no cryptographic material is needed — any certificate structure passes validation. Even after proper validation is wired in, the missing intra-batch duplicate check remains a structural gap: an equivocating prover holding a quorum could still exploit ordering within a batch.

---

### Recommendation

Add an intra-batch uniqueness check on round numbers in `processCerts`, analogous to the fix applied in OpenVM (checking that all `air_id`s are distinct before processing). Concretely, before the `partitionEithers` step, verify that no two certificates in `certsNotAlreadyInDb` share the same `getPerasCertRound`. If duplicates are found, throw a `PerasCertValidationError` (or a dedicated equivocation error) and disconnect from the peer. Additionally, implement the `validatePerasCert` stub with real cryptographic validation as tracked by the referenced GitHub issue.

---

### Proof of Concept

1. Peer connects and sends a single `ObjectDiffusion` batch containing two `PerasCert` values: `cert_fake` (round R, boosted block = attacker's weak block B′) and `cert_real` (round R, boosted block = canonical block B), in that order.
2. `processCerts` fetches `alreadyInDb`; round R is absent, so both certs pass the filter.
3. `validatePerasCert` (stub) returns `Right` for both.
4. `mapM_ addCert [cert_fake_validated, cert_real_validated]` is called.
5. `implAddCert` (STM) adds `cert_fake` for round R; `pcdsCertIds` now contains R.
6. `implAddCert` (STM) sees R already in `pcdsCertIds`, returns `PerasCertAlreadyInDB`; `processCerts` discards this result via `mapM_`.
7. The node's `getWeightSnapshot` now returns boost weight for B′, not B.
8. Chain selection compares candidates using this snapshot; the node may prefer a chain containing B′ over the canonical chain containing B. [1](#0-0) [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasCertDB/StateMachine.hs (L132-143)
```haskell
        -- Do not add equivocating certificates.
        AddCert cert -> all p model.certs
         where
          -- We should reject equivocating certificates, that is, certificates
          -- for the same round but boosting different blocks.
          -- So we should enforce: round = round' => boostedBlock = boostedBlock'
          p cert' =
            getPerasCertRound cert /= getPerasCertRound cert'
              || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
        GetWeightSnapshot -> True
        GetLatestCertSeen -> True
        GarbageCollect _slotNo -> True
```
