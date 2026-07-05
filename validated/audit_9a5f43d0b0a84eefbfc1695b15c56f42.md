### Title
Stub `validatePerasVote` / `validatePerasCert` Bypass Allows Any Peer to Forge Peras Quorum Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a deliberately incomplete (TODO-marked) `validatePerasVote` that performs only a stake-distribution lookup and no cryptographic verification. An unprivileged peer can send crafted `PerasVote` messages over the object-diffusion mini-protocol, impersonating any registered stake pool by supplying its publicly-known key hash. Once enough such votes accumulate to reach the configured quorum threshold, the node automatically forges a `ValidatedPerasCert` and feeds it into chain selection, artificially boosting an attacker-chosen block. The same stub unconditionally accepts every `PerasCert` as valid.

---

### Finding Description

The `BlockSupportsPeras` class declares two validation methods:

```haskell
validatePerasVote ::
  PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)

validatePerasCert ::
  PerasCfg blk -> PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance (the only instance that exists, explicitly labelled "TODO: degenerate instance for all blks to get things to compile") implements them as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr

validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [1](#0-0) 

The `PerasVote blk` data type in this instance carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — **no signature field**. There is therefore nothing to cryptographically verify; the sole check is whether the supplied `PerasVoterId` (a key hash) appears in the stake distribution. [2](#0-1) 

This `validatePerasVote` is the function wired into the inbound vote-processing pipeline. Both production pool writers call it:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) [4](#0-3) 

`processVotes` accepts the batch and calls `addVote` for every vote that passes this check: [5](#0-4) 

Inside `implAddVote`, the `PerasVoteDB` implementation itself also carries a TODO acknowledging the missing validation:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [6](#0-5) 

Once quorum is reached, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert` and `addPerasVoteWithAsyncCertHandling` enqueues it for chain selection: [7](#0-6) 

Chain selection then applies the certificate's boost weight to the targeted block, potentially switching the node to a non-canonical chain: [8](#0-7) 

The same unconditional acceptance applies to inbound `PerasCert` objects via `validatePerasCert`: [9](#0-8) 

---

### Impact Explanation

An unprivileged peer can forge a Peras quorum certificate for any block of its choice without possessing any stake pool private key. The forged certificate is accepted as `ValidatedPerasCert`, stored in the `PerasCertDB`, and used to boost the targeted block's chain-selection weight. This directly enables:

- **Unauthorized certificate acceptance**: the Peras vote/certificate verification bypass is the exact class of impact listed as Critical in the scope.
- **Chain-selection manipulation**: the boosted block gains artificial weight, potentially causing an honest node to prefer a non-canonical or adversarially-chosen chain over the honest chain, breaking the Peras fast-finality guarantee.

---

### Likelihood Explanation

The stake distribution is public ledger state. Every registered stake pool's key hash (`PerasVoterId`) is observable by any network participant. The object-diffusion mini-protocol is reachable by any peer that can establish a connection. No private key material, operator access, or stake majority is required. The attacker only needs to know the key hashes of enough pools to exceed the quorum threshold, then send one crafted `PerasVote` per pool.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasVote`: verify the BLS signature over `(pvVoteRound, pvVoteBlock)` using the voter's registered vote-verification key, and verify the VRF eligibility proof for non-persistent committee members. The `V1.PerasVote` type already carries `pvSignature` and `pvEligibilityProof` fields; the universal instance must be replaced with a concrete Cardano instance that uses them.

2. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate BLS signature over the certificate's election ID and candidate block, and verify that the set of voters meets the quorum threshold.

3. **Remove the universal `BlockSupportsPeras` instance** (or gate it behind a compile-time flag that is never enabled in production builds) to prevent the stub from being silently used.

---

### Proof of Concept

Given a node running with the universal `BlockSupportsPeras` instance and a known stake distribution:

1. Attacker reads the current stake distribution from the node's state-query endpoint to obtain the `PerasVoterId` (key hash) of every registered stake pool.

2. For each pool whose stake contributes toward quorum, attacker constructs:
   ```
   PerasVote { pvVoteRound = <current round>
             , pvVoteBlock = <attacker-chosen block point>
             , pvVoteVoterId = <pool key hash> }
   ```
   No signature is required because the `PerasVote` type in the universal instance has no signature field.

3. Attacker sends these votes in a batch via the object-diffusion mini-protocol. `processVotes` calls `validatePerasVote` for each; every vote whose `pvVoteVoterId` is in the stake distribution passes.

4. `implAddVote` calls `updatePerasRoundVoteStates`. Once the accumulated stake exceeds the quorum threshold, `VoteGeneratedNewCert cert` is returned and `AddedPerasVoteAndGeneratedNewCert cert` is produced.

5. `addPerasVoteWithAsyncCertHandling` enqueues the forged certificate via `addPerasCertAsync`.

6. `chainSelSync` processes the certificate: if the boosted block is not on the current chain, chain selection is re-run with the certificate's boost weight applied, potentially switching the node to the attacker's chosen block.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-112)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-142)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
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
