### Title
Peras Vote and Certificate Validation Unconditionally Bypasses Cryptographic Signature Checks, Enabling Fraudulent Chain Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance omits all cryptographic signature verification in both `validatePerasVote` and `validatePerasCert`. An unprivileged peer can submit `PerasVote` objects claiming to be any registered stake-pool voter, accumulate a fraudulent quorum, and cause the receiving node to accept a forged `PerasCert` that re-weights chain selection toward a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two validation entry points used on every inbound Peras object:

```haskell
validatePerasVote :: PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk
                  -> Either (PerasValidationErr blk) (ValidatedPerasVote blk)

validatePerasCert :: PerasCfg blk -> PerasCert blk
                  -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the codebase is the catch-all `instance StandardHash blk => BlockSupportsPeras blk`. Its implementations are:

**`validatePerasVote`** — only checks that the claimed voter ID exists in the stake distribution; no signature field exists in the `PerasVote blk` data type and no cryptographic check is performed:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

**`validatePerasCert`** — unconditionally returns `Right`, accepting every certificate regardless of content:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

The `PerasVote blk` data type in this instance carries no signature field at all — only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId`: [3](#0-2) 

This is the direct analog of the external report's signature replayability: because no signature is bound to a specific round or block, any vote message for any voter, any round, and any block passes validation. A vote "signed" (or not signed at all) for round R and block B is equally valid when replayed for round R′ and block B′.

The production inbound path in `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote` on every peer-supplied vote:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

Accepted votes are forwarded to `addPerasVoteWithAsyncCertHandling`, which generates a `PerasCert` once quorum is reached and enqueues it for chain selection via `addPerasCertAsync`: [5](#0-4) 

The certificate then triggers `chainSelectionForBlock` for the boosted block, potentially switching the node to a different chain: [6](#0-5) 

The real cryptographic infrastructure (`CryptoSupportsVoteSigning`, `verifyVoteSignature`, `verifyAggregateVoteSignature`) exists in the codebase and is used correctly in the `WFALS` and `EveryoneVotes` committee implementations, but is never wired into the `BlockSupportsPeras` instance that the production vote-diffusion path actually calls. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can:

1. Enumerate any set of registered stake-pool IDs from the public ledger state.
2. Craft `PerasVote` objects claiming to be those voters, for any round number and any block hash, with no valid signature required.
3. Submit them via the ObjectDiffusion mini-protocol. `processVotes` accepts the entire batch as long as each claimed voter ID appears in the stake distribution.
4. Once the accumulated fake votes exceed the quorum threshold, a `PerasCert` is generated and injected into chain selection.
5. The fraudulent certificate applies a Peras weight boost to an attacker-chosen block, causing the honest node to prefer a non-canonical or adversarially-selected chain.

This matches the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The attack requires only knowledge of registered stake-pool IDs (publicly available on-chain) and the ability to connect to a node via the standard peer-to-peer network. No key material, operator access, or stake majority is needed. The ObjectDiffusion mini-protocol is reachable by any peer. Likelihood is **High**.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (analogous to `pvSignature` in `PerasVote` in `Peras/Vote/V1.hs`).
2. Implement `validatePerasVote` to call `verifyVoteSignature` (or the appropriate committee-scheme equivalent) before accepting a vote, binding the signature to the specific `(roundNo, boostedBlock)` tuple so that a signature from one round cannot be replayed for another.
3. Implement `validatePerasCert` to call `verifyAggregateVoteSignature` and verify the quorum of constituent votes rather than unconditionally returning `Right`.
4. The existing `WFALS.implVerifyVote` and `EveryoneVotes.implVerifyCert` already demonstrate the correct pattern and should be used as the reference implementation. [8](#0-7) 

---

### Proof of Concept

**Setup**: A node running with the default `BlockSupportsPeras` instance. The attacker observes the current `PerasVoteStakeDistr` (available via ledger state queries) and identifies stake-pool IDs with sufficient combined stake to exceed the quorum threshold.

**Attack sequence**:

```
1. Attacker connects to the target node via the ObjectDiffusion mini-protocol.

2. Attacker selects a target block B (e.g., a block on a minority fork) and
   the current Peras round R.

3. Attacker constructs N PerasVote objects:
     PerasVote { pvVoteRound = R
               , pvVoteBlock = pointOf(B)
               , pvVoteVoterId = poolId_i }
   for i = 1..N, where sum(stake(poolId_i)) > quorumThreshold.
   No signature is required; the PerasVote data type has no signature field.

4. Attacker sends the batch to the target node via opwAddObjects.

5. processVotes calls validatePerasVote for each vote.
   validatePerasVote only checks lookupPerasVoteStake — all votes pass.

6. Each vote is added to the PerasVoteDB. Once quorum is reached,
   addPerasVoteWithAsyncCertHandling generates a PerasCert for (R, B).

7. The certificate is enqueued via addPerasCertAsync and processed by
   chainSelSync, which calls chainSelectionForBlock for block B.

8. The Peras weight boost causes the node to prefer the chain containing B,
   diverging from the canonical chain.
``` [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs (L79-85)
```haskell
  -- | Verify the signature of a vote candidate in a given election
  verifyVoteSignature ::
    VoteVerificationKey crypto ->
    ElectionId crypto ->
    VoteCandidate crypto ->
    VoteSignature crypto ->
    Either String ()
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-362)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
```
