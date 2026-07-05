### Title
Hardcoded Empty Stake Distribution in Production Permanently Disables All Peras Vote Acceptance, Silently Eliminating Peras Chain-Boosting Security — (`File: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs`)

---

### Summary

The production node-to-node handler wires the Peras vote inbound pool writer with a permanently empty `PerasVoteStakeDistr`. Because `validatePerasVote` requires a non-empty stake distribution to accept any vote, every inbound Peras vote unconditionally fails validation. `processVotes` then throws `PerasVoteValidationError` for every batch received from every peer, causing the peer to be disconnected and all Peras votes to be silently discarded. The result is that Peras certificate formation and chain boosting are completely non-functional in production, reducing chain-selection security to base Praos level.

---

### Finding Description

**Root cause — hardcoded empty stake distribution**

In `NodeToNode.hs` the `hPerasVoteDiffusionClient` handler calls `makePerasVotePoolWriterFromChainDB` and passes a permanently empty stake distribution:

```haskell
( makePerasVotePoolWriterFromChainDB
    systemTime
    -- TODO: when actual plumbing for Peras is ready, we will have to
    -- extract the committee selection data from the chainDB to pass
    -- it here, instead of relying on an empty the stake distribution.
    --
    -- Note that the empty stake distribution will cause all votes to
    -- be considered invalid.
    (pure (PerasVoteStakeDistr mempty))   -- ← always empty
    getChainDB
)
``` [1](#0-0) 

**Validation step — always returns `Left`**

`validatePerasVote` (the default instance for all blocks) calls `lookupPerasVoteStake`, which does a `Map.lookup` in the stake distribution. With `mempty` the map is always empty, so the lookup always returns `Nothing`, and the function always returns `Left PerasValidationErr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr          -- ← always taken
``` [2](#0-1) 

**Batch rejection — throws on any failure**

`processVotes` partitions validation results and throws `PerasVoteValidationError` if any vote fails. Because every vote fails, every batch from every peer throws:

```haskell
case partitionEithers validationResults of
  ([], validatedVotes) -> mapM_ (addVote . WithArrivalTime now) validatedVotes
  (errs, _)            -> throw (PerasVoteValidationError errs)  -- ← always taken
``` [3](#0-2) 

**Rethrow policy gap — exception not registered**

`consensusRethrowPolicy` lists every known exception type. `PerasVoteInboundException` (`PerasVoteValidationError`) is absent from the list. The framework comment states the default for unregistered exceptions is to disconnect the peer and allow reconnect after 10–20 s. Honest peers sending valid votes are therefore repeatedly disconnected in a tight cycle. [4](#0-3) 

**End-to-end attack path**

1. Any unprivileged peer connects and sends a batch of Peras votes via the `hPerasVoteDiffusionClient` mini-protocol.
2. `processVotes` reads the hardcoded empty `PerasVoteStakeDistr`.
3. `validatePerasVote` returns `Left PerasValidationErr` for every vote.
4. `processVotes` throws `PerasVoteValidationError`.
5. The unregistered exception triggers the default rethrow policy: peer disconnected.
6. No vote is ever stored; no quorum is ever reached; no Peras certificate is ever forged.
7. Peras chain boosting is permanently absent from chain selection.

---

### Impact Explanation

Peras is designed to boost chain-selection security beyond base Praos by allowing a quorum of committee members to certify a block, making it effectively irreversible. With all votes unconditionally rejected:

- No `ValidatedPerasVotesWithQuorum` is ever produced.
- No `PerasCert` is ever forged or added to the ChainDB.
- The `PerasWeightSnapshot` used in `compareChainDiffs` / `preferAnchoredCandidate` never reflects any Peras boost.
- Chain selection operates at base Praos security for all time.

This is a **High** impact chain-selection security regression: an unprivileged peer (or the mere act of running the Peras vote diffusion mini-protocol) causes the honest node to permanently operate with a less-secure chain-selection rule than the protocol intends, matching the scope criterion *"chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The condition is unconditional and deterministic. Every production node running this code with the Peras vote diffusion mini-protocol enabled will reject 100 % of inbound votes. No special attacker capability is required; the empty stake distribution is hardcoded in the production wiring path. The developers acknowledge the issue in the inline TODO comment.

---

### Recommendation

Replace the hardcoded `(pure (PerasVoteStakeDistr mempty))` with the actual committee selection data extracted from the `ChainDB` (as the TODO comment already prescribes). Until that plumbing is complete, the Peras vote diffusion mini-protocol should either be disabled at the network layer or the validation step should be skipped (accepting all structurally valid votes) so that votes are not silently discarded and honest peers are not disconnected.

Additionally, register `PerasVoteInboundException` and `PerasCertInboundException` in `consensusRethrowPolicy` with an appropriate policy (e.g., `theyBuggyOrEvil` for genuinely invalid votes, or a softer policy while the stake distribution plumbing is incomplete) so that the exception handling is explicit rather than relying on the default fallback.

---

### Proof of Concept

```
Peer → node: [PerasVote { pvVoteRound=R, pvVoteBlock=B, pvVoteVoterId=V }]

processVotes:
  alreadyInDb = {}                          -- vote not yet seen
  votesNotAlreadyInDb = [vote]
  validateVote vote:
    getStakeDistrSTM = PerasVoteStakeDistr (Map.empty)
    lookupPerasVoteStake vote (Map.empty) = Nothing
    → Left PerasValidationErr
  validationResults = [Left PerasValidationErr]
  partitionEithers → ([PerasValidationErr], [])
  → throw (PerasVoteValidationError [PerasValidationErr])

RethrowPolicy: PerasVoteInboundException not listed
  → default: disconnect peer, allow reconnect in 10–20 s

Result: vote never stored, quorum never reached, no certificate ever forged.
```

### Citations

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L184-201)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/RethrowPolicy.hs (L35-117)
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
    -- Dispatch on nested exception
    <> mkRethrowPolicy
      ( \ctx (ExceptionInLinkedThread _ e) ->
          runRethrowPolicy (consensusRethrowPolicy pb) ctx e
      )
```
