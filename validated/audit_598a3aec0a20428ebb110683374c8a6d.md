### Title
`processCerts` and `processVotes` use a degenerate `validatePerasCert`/`validatePerasVote` that unconditionally accepts all inbound Peras certificates and votes without any cryptographic verification - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

Both `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`. This resolves to the degenerate `BlockSupportsPeras` instance (explicitly marked `-- TODO: degenerate instance for all blks to get things to compile`) which unconditionally returns `Right` for every certificate, bypassing all cryptographic and structural validation. An unprivileged peer can send crafted `PerasCert` values targeting arbitrary blocks; these are accepted, stored in the `PerasCertDB`, and trigger chain selection via `addPerasCertAsync`, potentially causing the node to prefer a non-canonical chain. The same pattern applies to `validatePerasVote`, which skips signature verification entirely.

---

### Finding Description

**Root cause — wrong validation entry point called:**

In `PerasCert.hs`, both production pool writers hard-code the degenerate instance as the validation function:

```haskell
-- makePerasCertPoolWriterFromCertDB (line 103)
(validatePerasCert mkPerasParams)

-- makePerasCertPoolWriterFromChainDB (line 126)
(validatePerasCert mkPerasParams)
``` [1](#0-0) 

The `validatePerasCert` implementation that is actually called is the degenerate `BlockSupportsPeras` instance:

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
``` [2](#0-1) 

This is the **only** instance in scope, declared as a catch-all degenerate placeholder: [3](#0-2) 

The `processCerts` function relies entirely on this callback for validation:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces an empty error list, and every inbound certificate is unconditionally accepted.

**Same pattern for votes:**

`makePerasVotePoolWriterFromChainDB` (the production vote writer) passes:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [5](#0-4) 

The degenerate `validatePerasVote` only checks stake-distribution membership; it performs **no signature verification** and **no committee eligibility check**:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [6](#0-5) 

The proper entry point — `verifyVote` from the `VotingCommittee` class — performs full cryptographic signature verification and VRF eligibility checks: [7](#0-6) 

Neither `processCerts` nor `processVotes` calls `verifyVote`; they call the degenerate stubs instead.

**Downstream chain-selection impact:**

An accepted certificate is forwarded to `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. The chain-selection loop then calls `chainSelectionForBlock` for the boosted block, using `weightBoostOfFragment` to compare candidate chains: [8](#0-7) 

The default `perasWeight` is 15 (`PerasWeight 15`), meaning a single forged certificate adds 15 units of weight to any targeted block's chain, potentially overriding the honest chain. [9](#0-8) 

---

### Impact Explanation

**Critical — bypass of Peras certificate/vote verification enabling unauthorized chain-selection manipulation.**

An unprivileged peer can:
1. Send a crafted `PerasCert{pcCertRound = R, pcCertBoostedBlock = P}` for any block `P` in the VolatileDB.
2. The certificate passes `validatePerasCert` unconditionally.
3. The certificate is stored and triggers `chainSelectionForBlock` for `P`.
4. The node's chain selection adds `PerasWeight 15` to `P`'s chain, potentially causing a fork switch to a non-canonical chain.

For votes: an attacker knowing any `PerasVoterId` present in the stake distribution can forge votes (no signature required) for any block, accumulate quorum, and cause the node to forge and accept a certificate for an attacker-chosen block — with the same chain-selection consequence.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras votes and certificates is a standard peer-to-peer channel reachable by any connected peer without authentication. The `PerasVote` and `PerasCert` types carry no cryptographic material in the degenerate instance (no signature field on `PerasVote`, no aggregate-sig field on `PerasCert`), so crafting valid-looking objects requires only knowledge of a `PerasVoterId` (publicly observable from the stake distribution) and a target block hash (observable from the chain). No private keys are needed.

---

### Recommendation

Replace the hard-coded `validatePerasCert mkPerasParams` and `validatePerasVote mkPerasParams sd` calls with the proper `VotingCommittee`-backed verification path (`verifyVote` / `verifyCert`) that performs cryptographic signature verification and committee eligibility checks, as already implemented in `Committee/EveryoneVotes.hs` and `Committee/WFALS.hs`. Until a concrete `BlockSupportsPeras` instance with real cryptographic validation is wired in, the Peras object-diffusion mini-protocols should not be enabled in production.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Observe the VolatileDB (via chain-sync) to identify a block `P` on a candidate fork with hash `H` at slot `S`.
3. Construct `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = BlockPoint S H }`.
4. Send the certificate batch to the node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{..}`.
6. Certificate is stored; `addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
7. `chainSelSync` runs `chainSelectionForBlock` for `P`; `weightBoostOfFragment` adds `PerasWeight 15` to `P`'s chain.
8. If the honest tip is fewer than 15 blocks ahead of `P`, the node switches to the fork containing `P`, diverging from the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L95-101)
```haskell
  -- | Verify a vote cast by a committee member in a given election
  verifyVote ::
    VotingCommittee crypto committee ->
    Vote crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (EligibilityWitness crypto committee)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
