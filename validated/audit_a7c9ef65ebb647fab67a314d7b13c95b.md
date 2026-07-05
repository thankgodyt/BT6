### Title
Missing Cryptographic Authorization in Peras Vote and Certificate Validation Allows Unprivileged Peer to Forge Quorum and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used for all block types implements `validatePerasVote` with no cryptographic signature or VRF eligibility check, and implements `validatePerasCert` as an unconditional `Right` (no validation at all). An unprivileged peer can send crafted `PerasVote` messages impersonating any registered stake pool (voter IDs are public) and, once the quorum threshold is crossed, trigger automatic certificate generation and chain selection for an attacker-chosen block.

---

### Finding Description

The degenerate `BlockSupportsPeras` instance — explicitly marked as the production instance for all blocks — provides stub implementations of `validatePerasVote` and `validatePerasCert` that omit all cryptographic checks.

**`validatePerasVote`** only performs a stake-distribution lookup by voter ID:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

It does not verify:
- Any cryptographic signature over the vote body
- Any VRF eligibility proof
- Round number validity or timing constraints

**`validatePerasCert`** unconditionally returns `Right`:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

Zero validation is performed. Both functions carry explicit `TODO` comments acknowledging this:

> `-- TODO: perform actual validation against all possible 'PerasValidationErr' variants`

The inbound vote processing pipeline in `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote` as the sole gate before storing votes and triggering certificate generation:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

When quorum is reached, `addPerasVoteWithAsyncCertHandling` automatically calls `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` then calls `chainSelectionForBlock` for the boosted block, potentially switching the node's preferred chain.

---

### Impact Explanation

An unprivileged peer can:

1. Read the public stake distribution to enumerate valid `PerasVoterId` values.
2. Craft `PerasVote` messages for those voter IDs, targeting any block of the attacker's choice, without possessing any private key.
3. Submit them via the Peras vote diffusion mini-protocol.
4. Because `validatePerasVote` only checks voter ID membership, all votes pass validation and are stored in the `PerasVoteDB`.
5. Once the accumulated fake-vote stake crosses the quorum threshold, `votesReachQuorum` fires, a `ValidatedPerasCert` is forged internally, and `addPerasCertAsync` triggers chain selection for the attacker-chosen block.

Separately, a peer can also send a crafted `PerasCert` directly via the Peras cert diffusion mini-protocol; `validatePerasCert` accepts it unconditionally, and the same chain-selection path fires.

The result is that an honest node can be made to prefer a non-canonical or adversarially chosen chain, violating Peras's core security guarantee that only legitimately elected committee members can boost blocks.

---

### Likelihood Explanation

The attack requires only:
- Network connectivity to a target node (standard peer connection).
- Knowledge of the current stake distribution (fully public on-chain data).
- No private keys, no stake, no privileged access.

The Peras vote diffusion mini-protocol is designed to accept votes from any connected peer. The only barrier — `validatePerasVote` — is a single map lookup with no cryptographic content. This is trivially exploitable by any peer.

---

### Recommendation

1. Implement full cryptographic verification in `validatePerasVote`: verify the vote signature against the registered public key for the claimed `PerasVoterId`, and verify the VRF eligibility proof against the epoch nonce and committee selection parameters.
2. Implement full cryptographic verification in `validatePerasCert`: verify the aggregate BLS signature over the claimed voter set against the registered public keys, and verify each non-persistent voter's VRF output.
3. Until these checks are implemented, the Peras vote and certificate diffusion mini-protocols should not be enabled in production deployments.
4. Track completion via the referenced issue: `https://github.com/tweag/cardano-peras/issues/120`.

---

### Proof of Concept

```
-- Attacker connects as a normal peer and sends crafted votes.
-- stakeDistr is public on-chain data; no private keys needed.

let voterIds = Map.keys (unPerasVoteStakeDistr stakeDistr)
    targetBlock = <any block point the attacker wants to boost>
    roundNo = <current Peras round>

    -- Forge votes for every registered voter ID, no signatures required
    fakeVotes = [ PerasVote
                    { pvVoteRound   = roundNo
                    , pvVoteBlock   = targetBlock
                    , pvVoteVoterId = vid
                    }
                | vid <- voterIds ]

-- Send fakeVotes to the victim node via the Peras vote diffusion mini-protocol.
-- processVotes calls validatePerasVote, which only checks Map.lookup vid stakeDistr.
-- All votes pass. Once total stake >= quorum threshold, a certificate is auto-generated
-- and chainSelectionForBlock fires for targetBlock.
```

**Vulnerable call chain:**

`processVotes` → `validatePerasVote` (no sig check) → `PerasVoteDB.addVote` → `addPerasVoteWithAsyncCertHandling` → `addPerasCertAsync` → `chainSelSync (ChainSelAddPerasCert)` → `chainSelectionForBlock` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
