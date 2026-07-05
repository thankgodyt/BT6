### Title
Unconditional `validatePerasCert` Acceptance Enables Unauthorized Peras Certificate Injection and Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The catch-all `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted target; the certificate is accepted, stored, and fed directly into chain selection, where the Peras weight boost can cause the node to prefer a non-canonical fork.

### Finding Description
The degenerate instance at line 320 of `SupportsPeras.hs` is the only `BlockSupportsPeras` instance present in the repository:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

`validatePerasCert` ignores every field of `cert` and always returns `Right`. The inbound certificate path in `makePerasCertPoolWriterFromChainDB` calls this function directly:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`processCerts` in `PerasCert.hs` calls `validateCert` on every certificate received from a peer; if all pass (they always do), each is timestamped and forwarded to `addCert`. The ChainDB then queues a `ChainSelAddPerasCert` message. `chainSelSync` in `ChainSel.hs` processes it: if the boosted block is in the VolatileDB and not yet immutable, it calls `chainSelectionForBlock` with the boosted block, applying `perasWeight params` as extra chain weight. A sufficiently large boost can flip chain selection toward the attacker's fork.

The same structural gap exists in `validatePerasVote`: the `_params` argument is discarded and only a stake-distribution lookup is performed — no cryptographic signature over the vote is verified. An attacker who sends fake votes for every pool ID in the stake distribution will accumulate enough stake to trigger `votesReachQuorum`, which calls `forgePerasCert` (also a no-op) and injects a certificate through the vote path, bypassing even the certificate mini-protocol.

### Impact Explanation
An unprivileged peer can inject a `PerasCert` whose `pcCertBoostedBlock` points to any block currently in the VolatileDB. Chain selection applies the Peras weight boost unconditionally, potentially causing the honest node to switch away from the canonical chain to a fork the attacker controls or has seeded. Because the boost is applied before any ledger-level validation of the certificate's quorum proof, the node's chain-selection invariant — that only a legitimately certified block receives a weight boost — is violated. This constitutes a chain-selection integrity failure reachable by any connected peer.

### Likelihood Explanation
High. The attack requires only a standard peer connection. The attacker needs only the hash of a VolatileDB block (trivially obtained via ChainSync) and the ability to send a single well-formed CBOR-encoded `PerasCert` message. No stake, no cryptographic keys, and no privileged access are required. The Peras object-diffusion mini-protocol is wired into the production node kernel, making the path reachable on any node with Peras enabled.

### Recommendation
1. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature over the certificate's `(electionId, candidate)` pair against the committee's aggregate verification key, and confirms the claimed quorum weight meets the threshold.
2. Replace the stub `validatePerasVote` with a real implementation that verifies the per-voter BLS signature and, for non-persistent members, the VRF eligibility proof.
3. Until real validation is in place, gate the Peras certificate and vote mini-protocols behind a feature flag that is disabled by default in production builds, preventing the unauthenticated injection path from being reachable.

### Proof of Concept
1. Connect to a target node as a peer via the Peras certificate mini-protocol.
2. Obtain the `HeaderHash` of a block on a competing fork currently in the node's VolatileDB (via ChainSync `MsgRollForward`).
3. Construct a `PerasCert` with `pcCertRound = <any round not yet in the DB>` and `pcCertBoostedBlock = BlockPoint <slot> <adversarial hash>`.
4. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert` → unconditionally `Right`.
5. The certificate is stored in `PerasCertDB`; `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` finds the boosted block in the VolatileDB, calls `chainSelectionForBlock` with the extra `perasWeight` boost.
7. If the boost exceeds the canonical chain's length advantage, the node switches to the adversarial fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
