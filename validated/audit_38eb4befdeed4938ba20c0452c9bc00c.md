### Title
Unauthenticated Peras Certificate Pre-Population Enables Adversarial Chain-Weight Injection via First-Write-Wins Semantics — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function is a stub that unconditionally accepts any `PerasCert` received from a peer. Combined with the `PerasCertDB`'s first-write-wins semantics (one certificate per round), an unprivileged peer can pre-populate the certificate database for any Peras round with a certificate boosting an adversarial block. The legitimate certificate for that round is then silently discarded by `processCerts`, causing the node to permanently apply incorrect Peras weight boosts during chain selection.

---

### Finding Description

**Root cause 1 — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The default instance unconditionally returns `Right` for every certificate, regardless of content. No committee membership, quorum, or cryptographic proof is checked. The TODO comment at line 350 explicitly acknowledges this is incomplete.

**Root cause 2 — `processCerts` filters by round before calling `validateCert`:** [2](#0-1) 

The function snapshots `alreadyInDb` (the set of round numbers already stored), filters out any cert whose round is already present, and only then calls `validateCert`. This means: whichever cert for round R arrives first is accepted; all subsequent certs for round R are silently dropped before validation even runs.

**Root cause 3 — `implAddCert` enforces first-write-wins with no equivocation check:** [3](#0-2) 

The TODO at line 167 confirms that non-trivial validation logic is absent. The check at line 178 (`Set.member roundNo (pcdsCertIds pcds)`) only tests round-number uniqueness; it does not compare the boosted block of the incoming cert against the stored one. The test-model `precondition` explicitly excludes equivocating certificates from testing, but the production code has no such guard.

**The attack path (analog to the external report):**

The external report's pattern — *attacker pre-populates state that is checked as a uniqueness precondition, causing legitimate operations to be silently blocked* — maps directly here:

1. Attacker connects as a peer and sends a `PerasCert` for round R boosting adversarial block A via the Peras cert diffusion miniprotocol (`aPerasCertDiffusionClient`).
2. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
3. The cert is stored in `PerasCertDB`; round R is now in `pcdsCertIds`.
4. The legitimate cert for round R (boosting canonical block B) arrives from an honest peer.
5. `processCerts` filters it out at line 166 because `roundNo ∈ alreadyInDb`.
6. `getWeightSnapshot` now returns a `PerasWeightSnapshot` that boosts block A.
7. Chain selection (`preferAnchoredCandidate`) uses these weights; the node may prefer a candidate chain containing block A over the canonical chain. [4](#0-3) 

The `weights` snapshot read at line 634 feeds directly into `preferAnchoredCandidate`, so the injected boost is applied to every subsequent chain selection run until the certificate is garbage-collected.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

By injecting a certificate that boosts an adversarial block, the attacker causes the node's `PerasWeightSnapshot` to permanently assign Peras weight to the wrong block for that round. Chain selection then treats the adversarial fork as heavier than it actually is, potentially causing the node to switch to or retain a non-canonical chain. This violates the Peras protocol's safety guarantee that weight boosts reflect honest quorum decisions.

---

### Likelihood Explanation

**High.** The Peras cert diffusion miniprotocol is wired into the node-to-node stack and accepts inbound certificates from any connected peer. No stake, keys, or credentials are required to send a `PerasCert` message. The stub validator makes every syntactically well-formed certificate pass. A single malicious peer connection is sufficient to execute the attack for any round not yet in the local `PerasCertDB`.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras cert diffusion miniprotocol is active in production. Validation must verify committee membership, individual vote signatures, and that the aggregate stake meets the quorum threshold.
2. **Add an equivocation check in `implAddCert`**: if a cert for round R already exists and the new cert boosts a *different* block, the new cert should be rejected (or the conflict logged and the peer disconnected), not silently ignored.
3. **Gate the miniprotocol** behind a protocol-version or feature flag that is disabled until validation is complete, consistent with the existing TODO at `https://github.com/tweag/cardano-peras/issues/120`.

---

### Proof of Concept

```
1. Establish a peer connection to a target node.

2. Before any honest cert for round R arrives, send via the Peras cert
   diffusion miniprotocol:
     PerasCert { pcCertRound = R, pcCertBoostedBlock = <adversarial block A> }

3. processCerts calls validatePerasCert, which returns:
     Right ValidatedPerasCert { vpcCert = ..., vpcCertBoost = perasWeight params }
   (no actual validation performed)

4. implAddCert stores the cert; pcdsCertIds now contains R.

5. The honest cert for round R (boosting canonical block B) arrives.
   processCerts filters it: roundNo ∈ alreadyInDb → silently dropped.

6. getWeightSnapshot returns weights that boost block A.

7. chainSelectionForBlock reads these weights at:
     (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
   and passes them to preferAnchoredCandidate.

8. The node now treats any candidate chain containing block A as heavier
   than the canonical chain by the Peras boost amount, potentially
   switching to or retaining the adversarial fork.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
