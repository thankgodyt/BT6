### Title
Missing Cryptographic Validation in Peras Vote and Certificate Acceptance Allows Unauthorized Quorum and Certificate Forgery - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` and `validatePerasCert` implementations in the production `BlockSupportsPeras` instance are stubs that skip all cryptographic verification. An unprivileged peer can craft votes using any voter identity present in the public stake distribution — without possessing the corresponding private key — and have those votes accepted, counted toward quorum, and used to forge a fraudulent Peras certificate that boosts an attacker-controlled chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two critical validation methods: `validatePerasVote` and `validatePerasCert`. The universal instance for all `StandardHash blk` blocks, which is the instance used throughout the production vote-ingestion pipeline, implements both as stubs:

**`validatePerasVote`** — only checks that the `voterId` appears in the stake distribution. It performs no signature verification, no committee eligibility check, and no VRF proof validation:

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

**`validatePerasCert`** — unconditionally accepts every certificate:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

These stubs are called directly in the production vote-ingestion path. `processVotes` in `PerasVote.hs` calls `validatePerasVote` for every inbound vote before adding it to the `PerasVoteDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

Both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` use this same call site. Once a vote passes this stub validation, it is timestamped and passed to `addVote`, which calls `updatePerasRoundVoteStates` and accumulates stake toward quorum. When the quorum threshold is crossed, `forgePerasCert` is called and a `ValidatedPerasCert` is produced and stored.

The deduplication guard in `implAddVote` only prevents the *same* `(voterId, roundNo)` pair from being counted twice. It does not prevent an attacker from submitting votes for *different* voter IDs from the stake distribution, each of which passes the stub check and contributes its full stake weight.

---

### Impact Explanation

The Peras protocol uses certificates to boost the chain weight of a specific block. A fraudulent certificate — forged by accumulating fake votes that passed stub validation — carries the same `vpcCertBoost` weight as a legitimate one. Chain selection logic that incorporates Peras certificate weight will therefore prefer the attacker's boosted chain over the honest canonical chain. This constitutes:

- **Bypass of Peras voting/certificate checks** enabling unauthorized certificate acceptance (Critical tier).
- **Chain selection manipulation** causing honest nodes to prefer a non-canonical chain (High tier).

The `PerasVoteAlreadyInDB` deduplication guard does not mitigate this: the attacker uses *distinct* voter IDs (all publicly visible in the stake distribution), so each forged vote is treated as a new, unique vote.

---

### Likelihood Explanation

The stake distribution is a public ledger artifact. Any peer connected via the ObjectDiffusion mini-protocol can enumerate all valid voter IDs and their associated stake weights. Constructing a batch of forged votes requires only knowledge of the stake distribution — no private keys, no stake majority, no operator access. The attack is executable by any unprivileged network peer in a single batch submission to `processVotes`.

---

### Recommendation

1. Replace the stub `validatePerasVote` with a real implementation that verifies the cryptographic signature on the vote body (BLS or KES depending on the committee scheme) and checks committee eligibility (VRF proof for non-persistent members, persistent membership proof for persistent members), as defined in the `CryptoSupportsVotingCommittee` typeclass (`verifyVote`).
2. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate signature over the claimed voter set, as defined in `verifyCert`.
3. Connect the concrete committee implementations (`WFALS`, `EveryoneVotes`) to the `BlockSupportsPeras` validation methods rather than leaving the universal stub instance in place.
4. Track issue https://github.com/tweag/cardano-peras/issues/120 as a security-critical blocker before any Peras activation.

---

### Proof of Concept

1. Attacker reads the current `PerasVoteStakeDistr` (public ledger state) and identifies N voter IDs whose combined stake exceeds the quorum threshold.
2. For each voter ID `v_i`, attacker constructs a `PerasVote` with `pvVoteVoterId = v_i`, `pvVoteRound = R`, `pvVoteBlock = attacker_block_point`.
3. Attacker sends this batch to an honest node via the ObjectDiffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each vote. Since each `v_i` is present in `sd`, all votes return `Right ValidatedPerasVote { vpvVoteStake = stake_i }`.
5. Each validated vote is passed to `addVote`, which calls `updatePerasRoundVoteStates`. Stake accumulates in `ptvtTotalStake`.
6. When `stakeAboveThreshold cfg totalVoteStake` becomes true, `forgePerasCert` is called and a `ValidatedPerasCert` boosting `attacker_block_point` is stored.
7. The fraudulent certificate inflates the chain weight of `attacker_block_point`, causing the honest node's chain selection to prefer the attacker's chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-198)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L430-459)
```haskell
updateTargetVoteTally ::
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteTally blk ->
  PerasTargetVoteTally blk
updateTargetVoteTally
  vote
  ptvt@PerasTargetVoteTally
    { ptvtVotes
    , ptvtTarget
    , ptvtTotalStake
    } =
    assert (getPerasVoteTarget vote == ptvtTarget) $ do
      ptvt
        { ptvtVotes = pvaVotes'
        , ptvtTotalStake = pvaTotalStake'
        }
   where
    swapVote =
      Map.insertLookupWithKey
        (\_k old _new -> old)
        (getPerasVoteId vote)

    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```
