### Title
`validatePerasVote` Accepts Votes Without Signature or Block-Membership Verification, Enabling Fake-Vote Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasVote` implementation accepts any inbound Peras vote whose voter ID appears in the stake distribution, without verifying a cryptographic signature or that the voted-for block is on the canonical chain. An unprivileged peer can craft votes for an arbitrary block using any publicly-known pool ID, accumulate enough stake-weighted fake votes to reach quorum, and cause the node to forge a Peras certificate that boosts the weight of a non-canonical chain, corrupting chain selection.

---

### Finding Description

The default (catch-all) `BlockSupportsPeras` instance is defined for all `StandardHash blk` types: [1](#0-0) 

The `PerasVote blk` data type in this instance carries **no cryptographic signature field**: [2](#0-1) 

The `validatePerasVote` implementation only checks that the voter ID (`pvVoteVoterId`) is present in the stake distribution map. It performs no signature check, no round-number validity check, and no verification that `pvVoteBlock` refers to a block that actually exists on the chain: [3](#0-2) 

The `lookupPerasVoteStake` helper that drives this check only does a `Map.lookup` on the voter ID: [4](#0-3) 

This stub is called directly on every inbound vote received from a peer, in both the ChainDB-backed and VoteDB-backed pool writers: [5](#0-4) [6](#0-5) 

After passing this validation, votes are stored and fed into `updatePerasRoundVoteStates`, which calls `votesReachQuorum`. That function only checks that all votes share the same target and that total stake exceeds the quorum threshold — it does not re-verify signatures or block membership: [7](#0-6) 

If quorum is reached, `forgePerasCert` is called and a `ValidatedPerasCert` is produced for the attacker-chosen block, which is then submitted to `addPerasCertAsync` and used to boost that block's chain weight in chain selection.

---

### Impact Explanation

A `ValidatedPerasCert` for an attacker-chosen block causes `getPerasWeightSnapshot` to assign a `PerasWeight` boost to that block. Chain selection uses this weight when comparing candidate fragments. An attacker who can accumulate enough fake votes (using publicly-observable pool IDs from the stake distribution) to reach quorum can make an honest node assign a Peras weight boost to a non-canonical or adversarial block, causing it to be preferred over the honest canonical chain. This is a **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**, matching the High impact tier. [8](#0-7) 

---

### Likelihood Explanation

The stake distribution (`PerasVoteStakeDistr`) is derived from public ledger state and all pool IDs are observable on-chain. The `PerasVote blk` type carries no signature, so an attacker needs only to know a valid `PerasVoterId` (a `KeyHash StakePool`) to craft a vote that passes `validatePerasVote`. The object diffusion mini-protocol is reachable by any peer without authentication. The attacker must send enough fake votes to exceed the quorum threshold in stake, which requires spoofing multiple pool IDs — but all are publicly known. This is a realistic attack for any peer connected to the node. [9](#0-8) 

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (analogous to how the concrete `PerasVote` in `Peras/Vote/V1.hs` carries a `pvSignature` and `pvEligibilityProof`).
2. In `validatePerasVote`, verify the vote's signature against the voter's public key from the committee/stake distribution before accepting it.
3. Verify that `pvVoteBlock` refers to a block that is known to the local chain (i.e., exists in the VolatileDB or ImmutableDB) before accepting the vote.
4. Verify that `pvVoteRound` is within the valid window for the current slot.
5. Until the full implementation is in place, the stub instance should reject all votes (`Left PerasValidationErr`) rather than accepting any vote whose voter ID appears in the stake distribution. [10](#0-9) 

---

### Proof of Concept

1. Observe the current `PerasVoteStakeDistr` from the public ledger state; collect a set of `PerasVoterId` values (pool key hashes) whose combined stake exceeds the quorum threshold defined in `PerasCfg`.
2. For each collected pool ID, construct a `PerasVote blk` with:
   - `pvVoteRound` = any round number
   - `pvVoteBlock` = the `Point` of a non-canonical block (e.g., a stale fork tip)
   - `pvVoteVoterId` = the collected pool key hash
3. Send these votes to the target node via the Peras object diffusion mini-protocol.
4. Each vote passes `validatePerasVote` because `lookupPerasVoteStake` finds the voter ID in the distribution.
5. `updatePerasRoundVoteStates` accumulates the votes; once total stake exceeds the quorum threshold, `votesReachQuorum` returns `Just`, and `forgePerasCert` produces a `ValidatedPerasCert` for the non-canonical block.
6. The certificate is submitted via `addPerasCertAsync`; the non-canonical block receives a `PerasWeight` boost.
7. Chain selection now prefers the non-canonical chain over the honest canonical chain. [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-272)
```haskell
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
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L91-117)
```haskell
-- 'ChainDB' and thus properly handles the produced certs.
makePerasVotePoolWriterFromVoteDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since it is during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  PerasVoteDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
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
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```
