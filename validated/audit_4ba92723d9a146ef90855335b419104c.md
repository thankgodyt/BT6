### Title
Peras Vote and Certificate Validation Stubs Accept Any Peer-Supplied Object Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance provides stub implementations of `validatePerasCert` and `validatePerasVote` that perform no meaningful cryptographic validation. `validatePerasCert` unconditionally returns `Right` for every certificate. `validatePerasVote` only checks stake-distribution membership, with no signature, no round-number, and no block-validity check. Both stubs are wired directly into the live Peras vote/certificate ingest path, allowing an unprivileged peer to inject forged votes or certificates that influence Peras-weighted chain selection.

---

### Finding Description

**Root cause — stub validation in the only `BlockSupportsPeras` instance**

`SupportsPeras.hs` defines the single catch-all instance:

```haskell
instance StandardHash blk => BlockSupportsPeras blk where
```

Its `validatePerasCert` implementation unconditionally accepts every certificate:

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
``` [1](#0-0) 

Its `validatePerasVote` implementation only checks stake-distribution membership:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [2](#0-1) 

The `PerasVote` and `PerasCert` data types carry **no cryptographic signature field**, so there is nothing to verify even if the code attempted to:

```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound   :: PerasRoundNo
    , pvVoteBlock   :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }

  data PerasCert blk = PerasCert
    { pcCertRound        :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
``` [3](#0-2) 

**Analog to the external report**: the external bug checks only `length == numberOfAssets` when it must also check `length == 2 * numberOfAssets`. Here, `validatePerasVote` checks only `lookupPerasVoteStake` (one condition) when it must also verify cryptographic authenticity (the missing condition). The missing condition is the security-critical one.

**Production ingest path**

`makePerasVotePoolWriterFromChainDB` in `ObjectPool/PerasVote.hs` calls `validatePerasVote` for every vote received from a peer:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

`processVotes` accepts the entire batch if all votes pass, then stores them in `PerasVoteDB`: [5](#0-4) 

`implAddVote` in `PerasVoteDB/Impl.hs` calls `updatePerasRoundVoteStates`, which invokes `votesReachQuorum`. When quorum is reached, `forgePerasCert` produces a `ValidatedPerasCert` and `addPerasVoteWithAsyncCertHandling` forwards it to `addPerasCertAsync`: [6](#0-5) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, where it boosts the targeted block's Peras weight and can trigger a chain switch.

`votesReachQuorum` checks only that all votes target the same block and that total stake exceeds the threshold — it does not re-verify authenticity: [7](#0-6) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Read the public stake distribution to enumerate high-stake `PerasVoterId` values.
2. Construct `PerasVote { pvVoteRound = r, pvVoteBlock = targetBlock, pvVoteVoterId = highStakeId }` for enough IDs to exceed the quorum threshold.
3. Send the forged votes via the Peras vote diffusion mini-protocol.
4. `validatePerasVote` passes each vote (stake-distribution check succeeds; no signature check exists).
5. `votesReachQuorum` fires; `forgePerasCert` produces a `ValidatedPerasCert` for `targetBlock`.
6. The certificate is added to `PerasCertDB` and boosts `targetBlock`'s chain weight.
7. `chainSelSync` may switch the node's selection to the attacker-chosen chain.

This is an unauthorized Peras certificate acceptance leading to adversary-controlled chain selection — matching the **Critical: Bypass of Peras voting or certificate checks enabling unauthorized certificate acceptance** impact class.

---

### Likelihood Explanation

Peras is disabled by default (`rnFeatureFlags`). However, the validation stubs are wired into the live ingest path with **no feature-flag guard around the validation calls themselves**. Any node operator enabling Peras is immediately exposed. The attack requires only a network connection — no keys, no stake, no admin access. Voter IDs are public information derivable from the stake distribution.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote` and `PerasCert` before they are diffused or stored.
2. Implement proper BLS/DSIGN signature verification in `validatePerasVote` and `validatePerasCert`, replacing the stubs.
3. Until complete validation is implemented, gate the entire Peras vote/certificate ingest path behind the Peras feature flag so that enabling Peras without complete validation is structurally impossible.

---

### Proof of Concept

```
1. Connect to a Peras-enabled node via the Peras vote diffusion mini-protocol.
2. Query the public stake distribution; identify voter IDs whose combined stake
   exceeds perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin.
3. For each such voter ID, construct:
     PerasVote { pvVoteRound   = currentRound
               , pvVoteBlock   = targetBlock   -- attacker-chosen
               , pvVoteVoterId = highStakeId }
4. Send the forged votes to the node.
5. processVotes calls validatePerasVote for each vote.
   validatePerasVote: Map.lookup pvVoteVoterId stakeDistr => Just stake => Right ValidatedPerasVote
   All votes accepted.
6. implAddVote -> updatePerasRoundVoteStates -> votesReachQuorum fires.
7. forgePerasCert produces ValidatedPerasCert { pcCertBoostedBlock = targetBlock }.
8. addPerasVoteWithAsyncCertHandling -> addPerasCertAsync -> chainSelSync.
9. targetBlock receives Peras weight boost; node may switch selection to attacker-chosen chain.
```

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-348)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
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
