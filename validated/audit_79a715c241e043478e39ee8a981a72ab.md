### Title
Peer-Controlled Voter Identity Substitution in `validatePerasVote` Bypasses Cryptographic Authorization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasVote` without any cryptographic signature check. The voter identity (`pvVoteVoterId`) is taken directly from the peer-supplied `PerasVote` message and used only for a stake-distribution lookup. An unprivileged peer can forge votes for any legitimate pool ID, accumulate a quorum, trigger certificate generation for an attacker-chosen block, and cause the honest node to prefer a non-canonical chain via the Peras weight boost in chain selection.

---

### Finding Description

The catch-all `BlockSupportsPeras` instance — explicitly marked as the production instance for all block types — defines `PerasVote` without a signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- attacker-controlled
  }
``` [1](#0-0) 

`validatePerasVote` accepts a vote as valid if and only if the attacker-supplied `pvVoteVoterId` appears in the stake distribution — no signature is verified:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` simply does a `Map.lookup` on the voter ID from the vote itself — the identity is entirely peer-supplied: [3](#0-2) 

This is the same instance used in the production `processVotes` pipeline: [4](#0-3) 

A compounding issue: `validatePerasCert` in the same instance unconditionally returns `Right` for every peer-provided certificate, with no validation at all:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [5](#0-4) 

Accepted certificates are fed directly into `chainSelSync` → `ChainSelAddPerasCert`, which triggers chain selection for the boosted block: [6](#0-5) 

Chain selection uses `wsvWeightBoost` from the certificate to compute `wsvTotalWeight`, which determines which chain is preferred: [7](#0-6) 

---

### Impact Explanation

**High.** An unprivileged peer can:

1. Forge `PerasVote` messages claiming to be from any pool ID present in the public stake distribution.
2. Because `validatePerasVote` performs no signature check, all forged votes pass validation and are stored in `PerasVoteDB`.
3. Once forged votes accumulate past the quorum threshold (`stakeAboveThreshold`), `forgePerasCert` is called and a certificate is generated for an attacker-chosen block.
4. Alternatively, the peer can directly send a crafted `PerasCert` (which `validatePerasCert` accepts unconditionally).
5. The certificate's `vpcCertBoost` is added to the chain's `wsvWeightBoost`, causing the honest node to prefer the boosted (potentially non-canonical) fork over the canonical chain.

This matches the **High** impact category: "Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

---

### Likelihood Explanation

**High.** The ObjectDiffusion mini-protocol is open to any connected peer. The stake distribution is public ledger data, so an attacker trivially knows which voter IDs to impersonate. No key material, stake, or privileged access is required. The attack requires only crafting well-formed CBOR-encoded `PerasVote` or `PerasCert` messages.

---

### Recommendation

1. **`validatePerasVote`**: The `PerasVote` type must include a cryptographic signature field (as the V1 concrete type `Ouroboros.Consensus.Peras.Vote.V1.PerasVote` already does with `pvSignature`). `validatePerasVote` must verify this signature against the public key associated with the claimed `pvVoteVoterId` before accepting the vote.

2. **`validatePerasCert`**: `validatePerasCert` must verify the aggregate BLS signature in the certificate against the public keys of the claimed voters (as the `implVerifyCert` functions in `WFALS.hs` and `EveryoneVotes.hs` already demonstrate for the committee abstraction layer).

3. The degenerate catch-all instance should be replaced with a proper per-era instance that wires in the real committee-based verification logic before Peras is activated on any network.

---

### Proof of Concept

**Attack via forged votes:**

```
Attacker peer:
  1. Read PerasVoteStakeDistr (public ledger data) → obtain all PoolIds with stake
  2. For each PoolId p_i with stake s_i:
       send PerasVote { pvVoteRound = r, pvVoteBlock = attacker_block, pvVoteVoterId = p_i }
  3. validatePerasVote checks: Map.lookup p_i stakeDistr → Just s_i → Right (ValidatedPerasVote)
  4. After enough votes: stakeAboveThreshold → forgePerasCert → ValidatedPerasCert for attacker_block
  5. chainSelSync (ChainSelAddPerasCert) triggers chain selection
  6. wsvTotalWeight(attacker_chain) = blockNo + perasWeight > wsvTotalWeight(canonical_chain)
  7. Honest node switches to attacker's fork
```

**Attack via direct forged certificate (even simpler):**

```
Attacker peer:
  1. send PerasCert { pcCertRound = r, pcCertBoostedBlock = attacker_block }
  2. validatePerasCert → always Right (no checks)
  3. chainSelSync (ChainSelAddPerasCert) → chain selection triggered
  4. Honest node may switch to attacker's fork
```

The entry point is `objectDiffusionInbound` → `opwAddObjects` → `processVotes`/`processCerts`: [8](#0-7) [9](#0-8)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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
