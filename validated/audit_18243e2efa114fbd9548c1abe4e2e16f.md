### Title
Peras Certificate and Vote Verification Bypass via Degenerate `BlockSupportsPeras` Universal Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass places all Peras certificate and vote cryptographic verification in a pluggable per-block-type instance. A universal degenerate instance (`instance StandardHash blk => BlockSupportsPeras blk`) is the only instance in the codebase and is therefore used for all production block types. This instance defines `PerasCert blk` and `PerasVote blk` without any cryptographic signature fields, and `validatePerasCert` unconditionally returns `Right` (accepts every certificate), while `validatePerasVote` checks only stake-distribution membership with no signature check. The production inbound-certificate and inbound-vote pipelines call these functions directly. An unprivileged peer can therefore send structurally valid but cryptographically unauthenticated Peras certificates that are accepted, stored, and used to trigger chain selection for an arbitrary block.

---

### Finding Description

**Root cause — the degenerate universal instance**

`BlockSupportsPeras` is the typeclass that owns all Peras validation logic:

```haskell
class (Show (PerasCfg blk), NoThunks (PerasCert blk)) => BlockSupportsPeras blk where
  validatePerasCert :: PerasCfg blk -> PerasCert blk
                    -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)
  validatePerasVote :: PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk
                    -> Either (PerasValidationErr blk) (ValidatedPerasVote blk)
  ...
```

The only instance in the entire codebase is the degenerate universal one:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  data PerasCert blk = PerasCert
    { pcCertRound        :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }   -- ← no signature field

  data PerasVote blk = PerasVote
    { pvVoteRound   :: PerasRoundNo
    , pvVoteBlock   :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }   -- ← no signature field

  -- TODO: perform actual validation …
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
    -- ↑ always Right — no verification whatsoever

  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
    -- ↑ only checks stake-distribution membership; no signature check
``` [1](#0-0) 

Because the data types themselves carry no signature fields, there is no way to add verification later without replacing the instance entirely.

**Production call sites that consume these functions**

`makePerasCertPoolWriterFromChainDB` — the production writer used by the node — calls `validatePerasCert mkPerasParams` directly on every inbound certificate received from a peer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← degenerate instance
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , ...
    }
``` [2](#0-1) 

Similarly, `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote` on every inbound vote: [3](#0-2) 

`processCerts` / `processVotes` treat a `Right` result as proof of validity and forward the object to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain-selection consequence**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes it: if the boosted block is in the VolatileDB, it immediately calls `chainSelectionForBlock` for that block, giving it extra Peras weight: [5](#0-4) 

The `ValidatedPerasCert blk` type that flows through the entire ChainDB API is defined in terms of the degenerate instance's `PerasCert blk`: [6](#0-5) 

**Structural parallel to M-07**

| M-07 (OpenDollar) | This finding |
|---|---|
| Tax payment lives in `BasicActions` (pluggable delegatecall target) | Certificate/vote verification lives in `BlockSupportsPeras` (pluggable typeclass) |
| `ODSafeManager.modifySAFECollateralization` does not enforce tax | `ChainDB` inbound pipeline does not enforce cryptographic verification |
| User substitutes `FakeBasicActions` with no tax call | Universal degenerate instance has no signature fields and always returns `Right` |
| Result: tax bypassed, protocol fees lost | Result: certificate verification bypassed, arbitrary block boosted |

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` message containing any `PerasRoundNo` and any `Point blk` (block hash + slot). Because `validatePerasCert` unconditionally returns `Right`, the certificate is accepted as `ValidatedPerasCert`, stored in `PerasCertDB`, and triggers `chainSelectionForBlock` for the named block. If that block is present in the node's VolatileDB, it receives a Peras weight boost that can cause the node to switch to a fork it would otherwise not prefer — a chain-selection manipulation that constitutes a high-severity consensus safety failure: an honest node is made to prefer a non-canonical or adversarially chosen chain without any stake-majority requirement.

For votes: a peer that knows any valid `PerasVoterId` present in the current stake distribution can forge votes for that voter. If enough such forged votes accumulate to reach quorum, `votesReachQuorum` produces a `ValidatedPerasVotesWithQuorum`, `forgePerasCert` is called, and the resulting certificate is injected into the same chain-selection path above. [7](#0-6) 

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras votes and certificates is a peer-facing network protocol. Any connected peer — no keys, no stake, no operator access required — can send a `PerasCert` or `PerasVote` message. The degenerate instance is the only instance in the codebase (confirmed: `BlockSupportsPeras` appears in exactly one production source file). No guard in the inbound pipeline re-checks cryptographic validity after `validatePerasCert`/`validatePerasVote` returns `Right`.

---

### Recommendation

1. **Move the mandatory check into the core pipeline.** The inbound `processCerts` / `processVotes` functions should require a non-degenerate verification function as a precondition enforced at the call site, not delegated entirely to the typeclass instance. A structural type-level guarantee (e.g., a `VerifiedPerasCert` newtype that can only be constructed by a function that performs real cryptographic checks) would prevent the degenerate instance from satisfying the requirement.

2. **Add signature fields to `PerasCert blk` and `PerasVote blk` in the degenerate instance.** The current data types structurally cannot carry signatures, making it impossible to add verification without a breaking change. Introduce the signature fields now, even if the verification logic is a stub, so that the type system enforces that signatures are present before a certificate is accepted.

3. **Replace the universal instance with per-era instances.** The `-- TODO: degenerate instance for all blks to get things to compile` comment acknowledges this is a placeholder. Tracking issue `cardano-peras/issues/73` and `cardano-peras/issues/120` should be resolved before the Peras ObjectDiffusion protocol is enabled on any network where chain-selection weight is real.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to a node via the ObjectDiffusion mini-protocol for Peras certificates.
2. Peer sends a `PerasCert` message: `PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <hash of target block> }`.
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }`.
4. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
5. `chainSelSync` finds the target block in VolatileDB and calls `chainSelectionForBlock` with the boosted weight.
6. If the boosted block is on a competing fork, the node switches to that fork.

No cryptographic material, no stake, and no operator interaction is required from the attacker. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L241-271)
```haskell
-- It returns 'Nothing' if either of these conditions is not met.
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-452)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
      PerasCertTicketNo ->
      STM m (Map PerasCertTicketNo (m (WithArrivalTime (ValidatedPerasCert blk))))
  -- ^ Get all known Peras certs with a ticket number strictly greater than the
  -- given one, in ascending order. The values are 'm' actions to allow
  -- implementations with on-disk storage.
  , getPerasCertIds :: STM m (Set PerasRoundNo)
  -- ^ Get the set of all Peras certificate round numbers currently in the
  -- database.
```
