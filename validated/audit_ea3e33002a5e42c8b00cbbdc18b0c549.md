### Title
Peras Certificate and Vote Signature Verification Bypass via Stub `validatePerasCert`/`validatePerasVote` in ObjectDiffusion Inbound Path — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `ObjectDiffusion` inbound handlers for Peras certificates and votes call `validatePerasCert` and `validatePerasVote` before storing received objects. However, the concrete `BlockSupportsPeras` instance used in production is an explicitly-labelled "degenerate" stub: `validatePerasCert` unconditionally returns `Right` for every input (no signature check whatsoever), and `validatePerasVote` only checks stake-distribution membership without verifying the BLS vote signature. Any unprivileged peer connected via the node-to-node `ObjectDiffusion` mini-protocol can therefore inject forged Peras certificates or votes that are accepted and stored, directly manipulating chain selection via Peras weight boosts.

---

### Finding Description

**Root cause — stub validation in the universal `BlockSupportsPeras` instance**

`SupportsPeras.hs` defines a catch-all instance for all `StandardHash blk` blocks, explicitly annotated as a temporary placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
```

`validatePerasCert` **always** returns `Right` — it performs zero cryptographic verification. `validatePerasVote` only checks that the claimed voter ID appears in the stake distribution; it never verifies the BLS vote signature.

**Attacker-controlled entry path**

The `ObjectDiffusion` mini-protocol is a public node-to-node protocol. The inbound handler `objectDiffusionInbound` calls `opwAddObjects` on the `ObjectPoolWriter` for every batch of received objects:

```haskell
opwAddObjects objectsToAck   -- line 408, Inbound.hs
```

For certificates, `opwAddObjects` is wired to `processCerts … (validatePerasCert mkPerasParams) …`:

```haskell
opwAddObjects = \certs ->
  processCerts systemTime (ChainDB.getPerasCertIds chainDB)
    (validatePerasCert mkPerasParams)          -- stub: always Right
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
```

`processCerts` calls `validateCert` on each new certificate and only rejects the batch if any call returns `Left`. Because `validatePerasCert` always returns `Right`, every peer-supplied certificate passes and is forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection.

For votes, `opwAddObjects` is wired to `processVotes … (\vote -> … pure $ validatePerasVote mkPerasParams sd vote) …`:

```haskell
opwAddObjects = \votes ->
  processVotes systemTime (ChainDB.getPerasVoteIds chainDB)
    (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
    (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
    votes
```

`validatePerasVote` only checks `lookupPerasVoteStake vote stakeDistr`. An attacker who knows any voter ID present in the stake distribution (public information) can forge a vote for that voter ID with an arbitrary block target and arbitrary round number. No BLS signature is checked. If the attacker sends enough forged votes for the same target to exceed the quorum threshold, `updatePerasRoundVoteStates` inside `implAddVote` will forge a new certificate and add it to the chain.

**End-to-end exploit flow**

1. Attacker connects to a victim node as a normal peer via the node-to-node `ObjectDiffusion` protocol.
2. **Certificate forgery path**: Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversaryBlock }` for any round `r` and any block point `adversaryBlock`. `validatePerasCert` returns `Right` unconditionally. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` triggers chain selection with a Peras weight boost applied to `adversaryBlock`.
3. **Vote forgery path**: Attacker sends `PerasVote { pvVoteRound = r, pvVoteBlock = adversaryBlock, pvVoteVoterId = knownVoterId }` for each known voter ID in the stake distribution. `validatePerasVote` accepts each vote (stake lookup succeeds). Once accumulated stake exceeds the quorum threshold, a certificate is automatically forged and added to the chain.

---

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate/vote verification enabling unauthorized chain selection manipulation.**

Peras certificates apply a weight boost (`vpcCertBoost = perasWeight params`) to the boosted block during chain selection. An adversary who can inject a forged certificate for an adversary-controlled block causes honest nodes to prefer that block over the canonical chain, constituting a consensus safety failure. The attacker can:

- Force any honest node to apply a Peras weight boost to an adversary-chosen block, making a non-canonical fork appear heavier and preferred by chain selection.
- Manufacture a quorum of forged votes to trigger automatic certificate generation for an adversary-controlled block, with the same chain-selection consequence.
- Repeat across all connected peers to achieve network-wide divergence from the canonical chain.

This matches the **Critical** impact category: "Bypass of certificate/vote verification that enables unauthorized certificate acceptance."

---

### Likelihood Explanation

**High.** The entry point is the public node-to-node `ObjectDiffusion` mini-protocol, reachable by any peer without authentication or special privilege. The attacker needs only to know a voter ID present in the stake distribution (public on-chain data) and the round/block they wish to boost. The stub validation functions are wired directly into the production `makePerasCertPoolWriterFromChainDB` and `makePerasVotePoolWriterFromChainDB` paths with no feature flag or guard disabling them. The TODO comments confirm the stubs are intentional placeholders, not disabled code paths.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` and `validatePerasVote` before the `ObjectDiffusion` inbound path is enabled in production. For certificates, this must include verifying the aggregate BLS signature against the declared voter set (as the `WFALS`/`EveryoneVotes` committee implementations already do in `implVerifyCert`). For votes, this must include verifying the individual BLS vote signature and, for non-persistent voters, the VRF eligibility proof.
2. **Do not ship the degenerate `BlockSupportsPeras` instance** as the production instance for Cardano blocks. Replace it with a Cardano-era-specific instance that delegates to the real committee verification logic.
3. **Gate the `ObjectDiffusion` mini-protocol** behind a feature flag until real validation is in place, to prevent the stub from being reachable on a live network.

---

### Proof of Concept

An attacker peer sends a single `MsgReplyObjects` message containing:

```
PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversary block point> }
```

**Step 1**: `objectDiffusionInbound` receives the object and calls `opwAddObjects [cert]`.

**Step 2**: `processCerts` calls `validatePerasCert mkPerasParams cert`.

**Step 3**: The stub implementation executes:
```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```
returning `Right` unconditionally.

**Step 4**: `processCerts` sees no errors and calls `addCert (WithArrivalTime now validatedCert)`.

**Step 5**: `ChainDB.addPerasCertAsync` stores the certificate and triggers chain selection, applying `perasWeight params` as a boost to `adversaryBlock`.

No cryptographic material is required. The attacker needs only a valid peer connection and knowledge of any block point on the network. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L111-137)
```haskell
-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L119-152)
```haskell
-- | Create a pool writer from the 'ChainDB'.
-- This properly handles the produced certs by letting the ChainDB take care
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L404-411)
```haskell
            objectsToAck =
              catMaybes $
                (((Map.!) pendingObjects') <$> toList objectIdsToAck)

        opwAddObjects objectsToAck
        traceWith tracer $
          TraceObjectDiffusionInboundAddedObjects
            (NumObjectsProcessed (fromIntegral $ length objectsToAck))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-328)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

-- | Add a Peras vote to the VoteDB contained in the ChainDB, and if this
-- results in a new cert being generated, add that cert /asynchronously/ to
-- the ChainDB as well.
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```
