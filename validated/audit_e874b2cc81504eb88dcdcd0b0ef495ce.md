### Title
Batch-Rejection in Peras Object Diffusion Suppresses Valid Certificates/Votes, Weakening Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` and `PerasVote.hs`)

---

### Summary

`processCerts` and `processVotes` implement an all-or-nothing batch validation policy: if **any single** object in a peer-supplied batch fails validation, the **entire batch** is rejected and all valid objects in it are silently discarded. An unprivileged peer can exploit this to suppress valid Peras certificates or votes that would otherwise boost a block's chain-selection weight, causing the receiving node to prefer a less-secure chain.

---

### Finding Description

Both inbound processing functions share the same structural flaw:

**`processCerts`** (`PerasCert.hs`, lines 164–185):
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)   -- valid certs in batch are discarded
``` [1](#0-0) 

**`processVotes`** (`PerasVote.hs`, lines 178–201):
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (...) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    ([], validatedVotes) ->
      mapM_ (addVote . WithArrivalTime now) validatedVotes
    (errs, _) ->
      throw (PerasVoteInboundException errs)  -- valid votes in batch are discarded
``` [2](#0-1) 

The `throw` (synchronous, from `GHC.Exception`) propagates out of `opwAddObjects`, which is called directly from the inbound ObjectDiffusion protocol handler: [3](#0-2) 

The exception propagates to the `withPeer` bracket in `ouroboros-network`, which disconnects the peer — but the valid objects in the batch are permanently lost. The code comments explicitly acknowledge this design:

> "if /any/ certificate in the batch fails validation, the entire batch is rejected by throwing a `PerasCertInboundException`" [4](#0-3) 

The `ObjectPoolWriter` interface used by the inbound side is: [5](#0-4) 

---

### Impact Explanation

Peras certificates directly influence chain selection weight. When a valid certificate is added to the `PerasCertDB`, `chainSelectionForBlock` is triggered for the boosted block, potentially causing the node to switch to a heavier chain: [6](#0-5) 

If a valid certificate is suppressed, the node's chain selection does not account for the Peras weight boost. The node may remain on a chain that is less secure (lacking the Peras boost) rather than switching to the boosted chain. This is a chain selection error caused by an unprivileged peer, matching the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

For votes: suppressing valid votes prevents quorum from being reached, meaning no certificate is ever forged for that round, permanently eliminating the Peras weight boost for that round's target block.

---

### Likelihood Explanation

Any peer participating in the ObjectDiffusion miniprotocol can send a crafted batch. The attacker needs only to:
1. Know of a valid certificate or vote that is about to be diffused (observable from the network).
2. Craft one invalid certificate/vote with the same round number or a plausible-looking but invalid payload.
3. Bundle both into a single batch and send it to the target node before the valid object arrives from honest peers.

No privileged access, key material, or stake majority is required. The attack is repeatable across rounds.

---

### Recommendation

Replace the all-or-nothing batch rejection with per-object handling: validate and add each object independently, skipping (and optionally logging) invalid ones rather than discarding the entire batch. The peer should still be disconnected if it sends invalid objects, but valid objects in the same batch should be processed first before the disconnect occurs. This mirrors the remediation in the referenced report: introduce a more permissive mode that does not let a single failing element block all others.

---

### Proof of Concept

1. Node A is running with the ObjectDiffusion miniprotocol enabled for Peras.
2. A valid Peras certificate `C_valid` for round `R` boosting block `B` exists on the network.
3. Attacker peer `P` connects to Node A via ObjectDiffusion.
4. `P` announces two certificate IDs: `round(C_valid)` and `round(C_crafted_invalid)`.
5. Node A requests both. `P` responds with `[C_valid, C_crafted_invalid]` in one batch.
6. `processCerts` calls `validateCert` on both. `C_crafted_invalid` fails.
7. `partitionEithers` returns `(errs=[...], _)`, so `throw (PerasCertValidationError errs)` is executed.
8. `C_valid` is never passed to `addCert`. It is permanently lost from this interaction.
9. `P` is disconnected. Node A never adds `C_valid` to its `PerasCertDB`.
10. `chainSelectionForBlock` is never triggered for block `B` with the Peras boost.
11. Node A's chain selection does not account for the Peras weight of `B`, and it may remain on a less-secure chain. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L146-155)
```haskell
-- | Process a batch of inbound Peras certificates received from a peer.
--
-- Certificates whose round number is already present in the database (as
-- determined by @alreadyInDbSTM@) are silently skipped. The remaining
-- certificates are validated; if /any/ certificate in the batch fails
-- validation, the entire batch is rejected by throwing a
-- 'PerasCertInboundException' (which should make us disconnect from the distant
-- peer, see 'withPeer' bracket function from `ouroboros-network`). Otherwise,
-- each valid certificate is timestamped with the current wall-clock time and
-- added to the database via @addCert@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L408-411)
```haskell
        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/API.hs (L64-72)
```haskell
data ObjectPoolWriter objectId object m
  = ObjectPoolWriter
  { opwObjectId :: object -> objectId
  -- ^ Return the id of the specified object
  , opwAddObjects :: [object] -> m ()
  -- ^ Add a batch of objects to the objectPool.
  , opwHasObject :: STM m (objectId -> Bool)
  -- ^ Check if the object pool contains an object with the given id
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
