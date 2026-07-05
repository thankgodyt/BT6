### Title
Peras Vote and Certificate Validation Stubs Accept All Peer-Supplied Objects Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance — which is the catch-all instance applied to **all** block types including `CardanoBlock` — implements `validatePerasCert` as an unconditional `Right` (accepts every certificate without any check) and implements `validatePerasVote` without any cryptographic signature verification. An unprivileged peer can send crafted Peras votes via the object diffusion miniprotocol that will be accepted, accumulated to quorum, and used to forge certificates that influence chain selection, without any cryptographic proof of eligibility.

---

### Finding Description

The `BlockSupportsPeras` class defines two validation methods that are called on inbound peer-supplied objects:

**`validatePerasCert`** — always returns `Right`, performing zero validation:

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

**`validatePerasVote`** — only checks that the voter ID appears in the stake distribution map; no signature is verified:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

`lookupPerasVoteStake` only performs a `Map.lookup` on the voter ID:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
```

This instance is the **only** instance for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

The inbound vote processing path in `processVotes` calls this validation directly on peer-supplied votes:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

`processVotes` is wired into the object diffusion protocol via `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB`, both of which are reachable from any connected peer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

**Analog to the external report**: The external report describes missing chain ID and receiver address verification when processing VAAs — the message is accepted and executed without verifying it was intended for this chain or this recipient. Here, `validatePerasCert` accepts every certificate unconditionally and `validatePerasVote` accepts any vote whose voter ID appears in the stake distribution, without verifying the cryptographic signature that proves the voter actually cast that vote.

**Attack consequence**:

1. An attacker enumerates stake pool IDs from the public ledger (the `PerasVoteStakeDistr` is derived from the ledger state).
2. The attacker crafts `PerasVote` objects with valid voter IDs but arbitrary `pvVoteBlock` targets (pointing to a non-canonical or attacker-preferred block).
3. `validatePerasVote` passes because `lookupPerasVoteStake` finds the voter ID in the distribution — no signature is checked.
4. Votes accumulate in `updatePerasRoundVoteStates`; when the total stake exceeds the quorum threshold, `forgePerasCert` is called and a certificate is produced for the attacker's chosen block.
5. The certificate is inserted via `addPerasCertAsync`, which triggers chain selection. The boosted block gains `perasWeight` in the `PerasWeightSnapshot`, causing the node to prefer the attacker's target chain over the honest chain.

This matches the **Critical** impact scope: bypass of Peras certificate/vote checks that enables unauthorized certificate acceptance and chain selection manipulation. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The Peras object diffusion protocol is fully wired into the production diffusion layer. `makePerasVotePoolWriterFromChainDB` is the production writer used when the ChainDB is present. Any peer that can connect to the node's object diffusion endpoint can submit `PerasVote` objects. The stake distribution is public (derived from the ledger), so enumerating valid voter IDs requires no privileged access. The only prerequisite is that the Peras vote diffusion miniprotocol is active on the target node. The TODO markers confirm this is a known incomplete state, not an intentional design choice. [7](#0-6) 

---

### Recommendation

1. **`validatePerasCert`**: Implement actual certificate validation — verify the aggregate BLS signature over the election ID and candidate block using the committee's aggregate verification key. Return `Left` for any certificate that fails.

2. **`validatePerasVote`**: Add cryptographic signature verification. The vote must carry a valid signature from the claimed voter's key over `(roundNo, targetBlock)`. The existing `ProtocolHeaderSupportsKES`/`verifyVoteSignature` infrastructure in `Committee.WFALS` and `Committee.EveryoneVotes` shows the correct pattern.

3. **Round validity**: Both validators should also check that the vote/certificate's round number is within the acceptable window relative to the current slot, analogous to the `realHeaderInFutureCheck` guard on block headers.

4. **Chain membership**: `validatePerasVote` should verify that `pvVoteBlock` refers to a block that is actually present in the local VolatileDB or ImmutableDB before accepting the vote. [8](#0-7) [9](#0-8) 

---

### Proof of Concept

**Step 1**: Obtain the current `PerasVoteStakeDistr` from the node's ledger state (public information). Extract any `PerasVoterId` (stake pool key hash) with non-zero stake.

**Step 2**: Craft a `PerasVote`:
```haskell
PerasVote
  { pvVoteRound  = currentRound        -- any valid round number
  , pvVoteBlock  = attackerChosenPoint -- point of a non-canonical block
  , pvVoteVoterId = legitimateVoterId  -- any pool ID from the stake distribution
  }
```

**Step 3**: Send this vote (and enough copies with different voter IDs to exceed the quorum threshold) to the target node via the Peras object diffusion miniprotocol.

**Step 4**: `processVotes` calls `validatePerasVote mkPerasParams sd vote`. Since `legitimateVoterId` is in `sd`, the lookup succeeds and the vote is accepted as `ValidatedPerasVote` with the real stake weight — no signature was required.

**Step 5**: `updatePerasRoundVoteStates` accumulates the votes. Once total stake exceeds the quorum threshold, `forgePerasCert` produces a `ValidatedPerasCert` for `attackerChosenPoint`.

**Step 6**: The certificate is inserted via `addPerasCertAsync`. The `PerasWeightSnapshot` is updated, and chain selection now boosts `attackerChosenPoint`, potentially causing the node to switch to the attacker's preferred chain. [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-113)
```haskell
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-344)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L211-232)
```haskell
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L199-207)
```haskell
updatePerasRoundVoteState ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  PerasRoundVoteState blk ->
  Either (UpdateRoundVoteStateError blk) (PerasRoundVoteState blk)
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
```
