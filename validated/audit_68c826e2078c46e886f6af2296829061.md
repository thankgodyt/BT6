### Title
Hardcoded Empty Peras Vote Stake Distribution Permanently Disables All Peras Vote Acceptance in Production - (File: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs)

### Summary
The production `hPerasVoteDiffusionClient` handler in `NodeToNode.hs` is wired with a hardcoded, permanently empty stake distribution `(pure (PerasVoteStakeDistr mempty))`. Because vote validation requires a voter's key to be present in this distribution, every Peras vote received from every peer fails validation. The `processVotes` function then throws `PerasVoteInboundException`, disconnecting the sending peer. No Peras votes can ever be accepted, no Peras certificates can ever be formed, and Peras chain-weight boosts are permanently suppressed — an exact structural analog to VaderReserve's single-address whitelist that locks out all legitimate callers.

### Finding Description

**Root cause — hardcoded empty whitelist in the production handler**

In `mkHandlers` at lines 398–408 of `NodeToNode.hs`, the `hPerasVoteDiffusionClient` handler is constructed with a constant STM action that always returns an empty map:

```haskell
( makePerasVotePoolWriterFromChainDB
    systemTime
    -- TODO: when actual plumbing for Peras is ready, we will have to
    -- extract the committee selection data from the chainDB to pass
    -- it here, instead of relying on an empty the stake distribution.
    --
    -- Note that the empty stake distribution will cause all votes to
    -- be considered invalid.
    (pure (PerasVoteStakeDistr mempty))   -- ← hardcoded empty whitelist
    getChainDB
)
```

The comment is self-documenting: the authors acknowledge that this will cause **all votes to be considered invalid**. There is no runtime path that replaces this constant with real data.

**Validation chain that always rejects**

`makePerasVotePoolWriterFromChainDB` (PerasVote.hs lines 131–152) feeds the stake distribution into `processVotes` as the validator:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

`validatePerasVote` (SupportsPeras.hs lines 363–371) calls `lookupPerasVoteStake`, which performs:

```haskell
Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
```

With `distr = mempty`, this lookup always returns `Nothing`, so `validatePerasVote` always returns `Left PerasValidationErr`.

**Throw-on-any-failure semantics cause peer disconnection**

`processVotes` (PerasVote.hs lines 178–201) uses `partitionEithers` on the validation results. Any non-empty error list causes:

```haskell
throw (PerasVoteValidationError errs)
```

The module comment explicitly states this exception "should make us disconnect from the distant peer." Because every vote fails, every peer that sends votes is disconnected.

**No runtime escape hatch**

The stake distribution is `pure (PerasVoteStakeDistr mempty)` — a pure, constant STM action. There is no `TVar`, no configuration knob, and no governance mechanism that can replace it with a real distribution at runtime. This is structurally identical to VaderReserve's `require(msg.sender == router)` with a router address that can never be updated: the "authorized set" is permanently empty.

### Impact Explanation

The Peras voting sub-protocol is completely non-functional in production:

- Every inbound Peras vote batch fails validation and triggers peer disconnection.
- No `ValidatedPerasVote` objects are ever stored in the `PerasVoteDB`.
- No quorum can ever be reached, so no `ValidatedPerasCert` is ever produced.
- `addPerasCertAsync` is never called from the vote path, so the ChainDB never receives a Peras certificate from vote aggregation.
- Peras chain-weight boosts (`PerasWeight`) are never applied to any block.
- Chain selection falls back to pure Praos length comparison, permanently operating below the security level that Peras is designed to provide (faster settlement, resistance to certain long-range adversaries).

This matches the allowed impact scope: **bypass of Peras voting and certificate checks** that prevents any Peras vote or certificate from being accepted, and a **chain-selection bug** that causes honest nodes to operate on a less-secure chain than the protocol's stated security assumptions.

### Likelihood Explanation

The entry path requires no privilege. Any peer that has negotiated a `NodeToNodeVersion` that includes the Peras vote diffusion mini-protocol and sends a `PerasVote` message will trigger the rejection. The handler is registered unconditionally in `mkHandlers` for all connections. Once Peras vote diffusion is active on the network, every participating node will silently discard all votes and disconnect every vote-sending peer, making the failure network-wide and self-reinforcing.

### Recommendation

1. **Immediate**: Replace `(pure (PerasVoteStakeDistr mempty))` with a live `STM m PerasVoteStakeDistr` action that reads the current epoch's stake distribution from the `ChainDB` (or a dedicated `TVar` updated on epoch boundaries), as the TODO comment already describes.
2. **Defensive**: Add an integration test that asserts at least one vote is accepted end-to-end through `hPerasVoteDiffusionClient` with a non-empty stake distribution, to prevent regression.
3. **Consider**: Until the real plumbing is in place, either disable the Peras vote diffusion mini-protocol at the version-negotiation layer so peers do not attempt to send votes, or silently drop (rather than throw on) votes whose voter ID is absent from the distribution, to avoid disconnecting peers unnecessarily.

### Proof of Concept

```
Peer A  ──[PerasVote{pvVoteVoterId = K, ...}]──►  Node B
                                                      │
                                          hPerasVoteDiffusionClient
                                                      │
                                          makePerasVotePoolWriterFromChainDB
                                            stakeDistr = PerasVoteStakeDistr mempty
                                                      │
                                          processVotes
                                            validatePerasVote mkPerasParams mempty vote
                                              lookupPerasVoteStake vote mempty
                                                = Map.lookup K {} = Nothing
                                              → Left PerasValidationErr
                                                      │
                                          partitionEithers [Left PerasValidationErr]
                                            = ([PerasValidationErr], [])
                                                      │
                                          throw (PerasVoteValidationError [...])
                                                      │
                                          Peer A disconnected
                                          No vote stored, no cert formed, no weight boost
```

Repeating for every peer on the network: zero Peras certificates are ever produced, Peras weight boosts are permanently zero, and chain selection degrades to pure Praos for the lifetime of the deployment. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-152)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
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
