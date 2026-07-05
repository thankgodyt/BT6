### Title
Adversarial Peer Can Suppress Valid Peras Votes/Certificates via Whole-Batch Rejection on Single Invalid Item - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`)

---

### Summary

`processVotes` and `processCerts` reject an **entire inbound batch** of Peras votes/certificates when **any single item** fails validation, discarding all valid items in the batch. An unprivileged peer can exploit this by mixing legitimately-observed valid votes with one crafted invalid vote, causing the victim node to permanently discard the valid votes and disconnect. The same structural flaw exists in the certificate path (`processCerts`).

---

### Finding Description

In `processVotes` (lines 178–201 of `PerasVote.hs`), the function:

1. Filters out votes already in the DB.
2. Validates **all** remaining votes inside a single `atomically` block via `mapM validateVote`.
3. Calls `partitionEithers` on the results — which correctly separates valid from invalid votes.
4. **If the error list is non-empty, throws `PerasVoteInboundException` and discards the entire batch**, including the valid votes that `partitionEithers` already isolated. [1](#0-0) 

The comment at line 165 explicitly documents the design choice: "if *any* vote in the batch fails validation, the entire batch is rejected." The valid votes in `validatedVotes` are silently thrown away.

The identical pattern exists in `processCerts`: [2](#0-1) 

`PerasVoteInboundException` and `PerasCertInboundException` are **not listed** in `consensusRethrowPolicy`, so they fall through to the network layer's default policy: disconnect from the peer and allow reconnect after ~10–20 s. [3](#0-2) 

The inbound handler calls `opwAddObjects objectsToAck` (line 408 of `Inbound.hs`), which is wired directly to `processVotes`/`processCerts` via `makePerasVotePoolWriterFromChainDB` / `makePerasCertPoolWriterFromChainDB`: [4](#0-3) 

---

### Impact Explanation

An adversarial peer can:

1. Observe valid Peras votes from committee members already propagating on the network.
2. Craft one invalid vote (e.g., wrong round number, bad voter ID, or a signature that fails `validatePerasVote`).
3. Send a batch `[V1_valid, V2_valid, …, V_bad]` to the victim node.
4. `processVotes` validates all items, finds `V_bad` invalid, and throws `PerasVoteInboundException` — discarding `V1_valid`, `V2_valid`, … entirely.
5. The victim disconnects; the adversary reconnects after ~10–20 s and repeats.

Valid votes from committee members are systematically suppressed from this peer. Because Peras certificates are formed by accumulating votes to quorum, and certificates boost blocks in chain selection, preventing a node from accumulating votes can delay or prevent certificate formation. A node that cannot form or observe certificates may diverge from the honest network's boosted-block preference, materially weakening Peras vote/certificate authorization.

This is the direct analog of the external report: a single crafted item in a collection causes the entire operation to fail, blocking legitimate items from being processed.

---

### Likelihood Explanation

Any unprivileged peer can mount this attack:
- No key compromise is required; the adversary only needs to observe valid votes already on the network.
- Crafting one invalid vote is trivial (e.g., flip a bit in the voter ID or round number).
- The attack is repeatable every ~10–20 s (reconnect window).
- The attack is reachable via the production `hPerasVoteDiffusionClient` / `hPerasCertDiffusionClient` handlers wired in `NodeToNode.hs`.

---

### Recommendation

Process votes individually: accept valid votes and only reject/penalise the invalid ones. The `partitionEithers` result already isolates valid votes — the fix is to add `validatedVotes` to the pool unconditionally and only disconnect (or log) for the invalid subset. Optionally, disconnect if the ratio of invalid votes exceeds a threshold to preserve the anti-spam property.

---

### Proof of Concept

```
1. Adversary connects to victim via PerasVoteDiffusion miniprotocol.
2. Adversary observes valid votes V1, V2, V3 from committee members on the network.
3. Adversary crafts V_bad (e.g., PerasVote with pvVoteRound = maxBound, invalid voter).
4. Adversary sends batch [V1, V2, V3, V_bad] via MsgObjects.
5. objectDiffusionInbound calls opwAddObjects [V1, V2, V3, V_bad]
   → processVotes validates all four.
   → partitionEithers returns ([err_bad], [V1', V2', V3']).
   → throw (PerasVoteValidationError [err_bad])   -- V1', V2', V3' discarded.
6. Exception propagates out of objectDiffusionInbound.
7. Not matched by consensusRethrowPolicy → default: ShutdownPeer (disconnect).
8. Adversary reconnects after ~10-20s, repeats from step 4.
9. V1, V2, V3 are never added to victim's PerasVoteDB from this peer.
``` [5](#0-4) [6](#0-5)

### Citations

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/RethrowPolicy.hs (L35-112)
```haskell
-- Exception raised during interaction with the peer
--
-- The list below should contain an entry for every type declared as an
-- instance of 'Exception' within ouroboros-consensus.
--
-- If a particular exception is not handled by any policy, a default
-- kicks in, which currently means logging the exception and disconnecting
-- from the peer (in both directions), but allowing a reconnect within a saall
-- delay (10-20s). This is fine for exceptions that only affect that peer.  It
-- is however essential that we handle exceptions here that /must/ shut down the
-- node (mainly storage layer errors).
--
-- TODO: Talk to devops about what they should do when the node does
-- terminate with a storage layer exception (restart with full recovery).
consensusRethrowPolicy ::
  forall blk.
  (Typeable blk, StandardHash blk) =>
  Proxy blk ->
  RethrowPolicy
consensusRethrowPolicy pb =
  mkRethrowPolicy (\_ctx (_ :: DbMarkerError) -> shutdownNode)
    -- Any exceptions in the storage layer should terminate the node
    --
    -- NOTE: We do not catch IOExceptions here; they /ought/ to be caught
    -- by the FS layer (and turn into FsError). If we do want to catch
    -- them, we'd somehow have to distinguish between IO exceptions
    -- arising from disk I/O (shutdownNode) and those arising from
    -- network failures (SuspendConsumer).
    <> mkRethrowPolicy (\_ctx (_ :: DbMarkerError) -> shutdownNode)
    <> mkRethrowPolicy (\_ctx (_ :: DbLocked) -> shutdownNode)
    <> mkRethrowPolicy (\_ctx (_ :: ChainDbFailure blk) -> shutdownNode)
    <> mkRethrowPolicy
      ( \_ctx (e :: VolatileDBError blk) ->
          case e of
            VolatileDB.ApiMisuse{} -> ourBug
            VolatileDB.UnexpectedFailure{} -> shutdownNode
      )
    <> mkRethrowPolicy
      ( \_ctx (e :: ImmutableDBError blk) ->
          case e of
            ImmutableDB.ApiMisuse{} -> ourBug
            ImmutableDB.UnexpectedFailure{} -> shutdownNode
      )
    <> mkRethrowPolicy (\_ctx (_ :: FsError) -> shutdownNode)
    -- When the system clock moved back, we have to restart the node.
    <> mkRethrowPolicy (\_ctx (_ :: SystemClockMovedBackException) -> shutdownNode)
    -- Some chain DB errors are indicative of a bug in our code, others
    -- indicate an invalid request from the peer. If the DB is closed
    -- entirely, it will only be reopened after a node restart.
    <> mkRethrowPolicy
      ( \_ctx (e :: ChainDbError blk) ->
          case e of
            ClosedDBError{} -> shutdownNode
            ClosedFollowerError{} -> ourBug
            InvalidIteratorRange{} -> theyBuggyOrEvil
      )
    -- We have some resource registries that are used per-connection,
    -- and so if we have ResourceRegistry related exception, we close
    -- the connection but leave the rest of the node running.
    <> mkRethrowPolicy (\_ctx (_ :: RegistryClosedException) -> ourBug)
    <> mkRethrowPolicy (\_ctx (_ :: ResourceRegistryThreadException) -> ourBug)
    <> mkRethrowPolicy (\_ctx (_ :: TempRegistryException) -> ourBug)
    -- An exception in the block fetch server meant the client asked
    -- for some blocks we used to have but got GCed. This means the
    -- peer is on a chain that forks off more than @k@ blocks away.
    <> mkRethrowPolicy (\_ctx (_ :: BlockFetchServerException) -> distantPeer)
    -- Peras components as part of the ChainDB can create exceptions, see
    -- https://github.com/tweag/cardano-peras/issues/216
    <> mkRethrowPolicy
      ( \_ctx (e :: PerasVoteDbError blk) ->
          case e of
            MultipleWinnersInRound{} -> ourBug -- TODO: should we instead shutdown the node?
            ForgingCertError{} -> ourBug
      )
    -- Some chain sync client exceptions indicate malicious behaviour,
    -- others merely mean that we should disconnect from this client
    -- because we have diverged too much.
    <> mkRethrowPolicy (\_ctx (_ :: ChainSyncClientException) -> theyBuggyOrEvil)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L391-410)
```haskell
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L404-412)
```haskell
            objectsToAck =
              catMaybes $
                (((Map.!) pendingObjects') <$> toList objectIdsToAck)

        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))

```
