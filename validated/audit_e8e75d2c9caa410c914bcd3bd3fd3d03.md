### Title
Peras Vote and Certificate Validation Performs No Cryptographic Signature Check, Allowing Any Peer to Forge Votes and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` and `validatePerasCert` implementations in the `BlockSupportsPeras` instance accept inbound Peras votes and certificates from peers without performing any cryptographic signature verification. `validatePerasCert` unconditionally returns `Right` for every certificate it receives, and `validatePerasVote` only checks that the claimed voter ID exists in the stake distribution — it never verifies that the sender cryptographically controls the key corresponding to that voter ID. Both functions are wired into the live production inbound-processing path. An unprivileged peer can therefore forge votes for any stake pool or forge certificates for any block, causing the node to boost an attacker-chosen block in chain selection.

---

### Finding Description

**Vulnerability class:** Bypass of Peras voting and certificate checks — identity claims in inbound protocol messages are never validated against any cryptographic proof.

**Root cause — `validatePerasCert` (unconditional accept):**

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

Every `PerasCert` received from any peer is immediately stamped as `ValidatedPerasCert` with full boost weight. No field of the certificate is checked. [1](#0-0) 

**Root cause — `validatePerasVote` (stake-only check, no signature):**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check is whether `pvVoteVoterId` (a `KeyHash StakePool`) appears in the stake distribution. The `PerasVote blk` data type carries no signature field at all, so there is nothing to verify:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- just a KeyHash, no signature
  }
``` [2](#0-1) 

**Production call sites — both functions are wired into the live inbound path:**

`makePerasVotePoolWriterFromChainDB` calls `validatePerasVote` for every batch of votes received from a peer:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams` for every batch of certificates received from a peer:

```haskell
(validatePerasCert mkPerasParams)
...
(void . ChainDB.addPerasCertAsync chainDB)
``` [4](#0-3) 

After passing "validation", a certificate is handed to `ChainDB.addPerasCertAsync`, which triggers `chainSelSync` and can switch the node to a different chain: [5](#0-4) 

**Two-stage validation gap (direct analog to the external report):**

```
Stage 1: Voter/certifier identity exists in stake distribution ✅ IMPLEMENTED (votes only)
  └─ lookupPerasVoteStake checks pvVoteVoterId ∈ stakeDistr

Stage 2: Cryptographic proof that sender controls that identity ❌ MISSING
  └─ No signature field on PerasVote blk
  └─ validatePerasCert performs zero checks
```

---

### Impact Explanation

**Impact: Critical — bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.**

**Attack vector A — direct certificate forgery (zero prerequisites):**
1. Attacker crafts `PerasCert { pcCertRound = r, pcCertBoostedBlock = attackerBlock }` for any block `attackerBlock` in the VolatileDB.
2. Sends it via the ObjectDiffusion certificate mini-protocol.
3. `validatePerasCert` returns `Right` unconditionally.
4. `ChainDB.addPerasCertAsync` triggers chain selection; `chainSelSync` boosts `attackerBlock` with full `perasWeight`.
5. If `attackerBlock` is on a fork, the node may switch to that fork.

**Attack vector B — vote-based certificate forgery:**
1. Attacker reads the public ledger state to enumerate stake pool key hashes (`PerasVoterId` values).
2. For each pool with sufficient stake, crafts `PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock, pvVoteVoterId = victimPoolId }`.
3. Sends the batch; `validatePerasVote` accepts each vote (only checks stake distribution membership).
4. Once accumulated votes exceed the quorum threshold, `PerasVoteDB` forges a certificate for `attackerBlock` and triggers chain selection.

Both vectors allow an unprivileged peer to make an honest node prefer a non-canonical chain, violating chain selection safety.

---

### Likelihood Explanation

**Likelihood: High.**

- The ObjectDiffusion mini-protocol is open to any connected peer; no special role (validator, SPO) is required.
- Stake pool key hashes are public ledger data; no secret material is needed.
- Attack vector A (direct certificate forgery) requires zero knowledge of the stake distribution.
- The attack is cheap and repeatable.

---

### Recommendation

1. **Add a signature field to `PerasVote blk`** (analogous to `pvSignature` in `Peras.Vote.V1.PerasVote`) and verify it in `validatePerasVote` against the verification key derived from `pvVoteVoterId`.
2. **Implement real certificate verification in `validatePerasCert`**: verify the aggregate BLS signature over the claimed voters and the claimed boosted block, and confirm each claimed voter seat index maps to a legitimate committee member.
3. **Remove the degenerate `instance StandardHash blk => BlockSupportsPeras blk`** stub (or gate it behind a compile-time flag) so that the compiler enforces that every production block type provides a real implementation before the Peras code paths are activated. [6](#0-5) 

---

### Proof of Concept

```
1. Node is running with Peras enabled and connected to the attacker's peer.

2. Attacker reads the current ledger state to find any block hash H in the
   VolatileDB (e.g., a block on a minority fork).

3. [Attack vector A — direct cert forgery]
   Attacker sends via the cert ObjectDiffusion protocol:
     PerasCert { pcCertRound = 999, pcCertBoostedBlock = H }

4. processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight })

5. ChainDB.addPerasCertAsync is called with the forged ValidatedPerasCert.

6. chainSelSync triggers chainSelectionForBlock for H.
   If H is on a fork that is now heavier (due to the boost), the node
   switches to that fork — accepting a non-canonical chain.

[Attack vector B — vote-based cert forgery]
3b. Attacker enumerates N stake pool IDs from the ledger (public data).
    For each pool_i with stake s_i, sends:
      PerasVote { pvVoteRound = 999, pvVoteBlock = H, pvVoteVoterId = pool_i }

4b. processVotes calls validatePerasVote for each vote.
    lookupPerasVoteStake finds pool_i in stakeDistr → returns Right.

5b. Once sum(s_i) > quorum threshold, PerasVoteDB forges a certificate
    for H and calls ChainDB.addPerasVoteWithAsyncCertHandling.

6b. Same chain selection outcome as vector A.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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
