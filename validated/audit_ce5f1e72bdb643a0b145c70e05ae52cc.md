### Title
Peras Vote and Certificate Signature Validation Bypass Allows Unauthorized Chain Boosting - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance used for all block types performs no cryptographic signature verification on inbound Peras votes or certificates. `validatePerasVote` only checks stake-distribution membership, and `validatePerasCert` unconditionally accepts every certificate. An unprivileged peer can forge votes attributed to any registered stake pool, accumulate a fake quorum, and cause the node to accept unauthorized Peras certificates that boost arbitrary blocks, directly affecting chain selection.

### Finding Description

The `BlockSupportsPeras` typeclass defines two critical validation methods:

```haskell
validatePerasCert ::
  PerasCfg blk -> PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only concrete instance in the codebase is the universal degenerate instance `instance StandardHash blk => BlockSupportsPeras blk`. Its implementations are:

**`validatePerasCert`** — unconditionally returns `Right`, accepting every certificate without any check:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

**`validatePerasVote`** — only checks that the claimed voter ID (`pvVoteVoterId`) exists in the stake distribution map. No cryptographic signature is present in the `PerasVote blk` data type for this instance, and none is verified:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The `PerasVote blk` data type for this instance carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — no signature field at all. Any peer can construct a `PerasVote` claiming to be any registered stake pool voter and it will pass validation.

The TODO comments in the source explicitly acknowledge the missing validation:

```
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
```

and in `PerasVoteDB/Impl.hs`:

```
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

### Impact Explanation

This is a **Critical bypass of Peras vote and certificate signature validation**. An unprivileged peer can:

1. Craft `PerasVote` messages claiming to be any `PerasVoterId` present in the stake distribution.
2. Send enough such forged votes to exceed the quorum threshold (`stakeAboveThreshold`).
3. The node's `processVotes` pipeline accepts all of them as `ValidatedPerasVote` values.
4. The `PerasVoteDB` aggregates them, reaches quorum, and calls `forgePerasCert` to produce a `ValidatedPerasCert`.
5. That certificate boosts an arbitrary block, directly influencing chain selection via the Peras weight mechanism.

Additionally, `validatePerasCert` accepts any inbound certificate unconditionally, so a peer can also directly inject a forged certificate for any round and block without needing to go through the vote aggregation path.

This matches the allowed impact: **Critical — bypass of certificate/vote verification that enables unauthorized certificate acceptance**, and **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

### Likelihood Explanation

**High.** The attack entry point is the standard Peras vote mini-protocol (`ObjectDiffusion`), reachable by any peer that connects to the node. No special privileges, keys, or stake are required — the attacker only needs to know the `PerasVoterId` (a `KeyHash StakePool`) of registered stake pools, which is public on-chain information. The forged votes pass the only check performed (stake-distribution membership lookup) because the voter ID is attacker-controlled. The code is in production files and is actively wired into the `ChainDB` via `makePerasVotePoolWriterFromChainDB`.

### Recommendation

1. Add a cryptographic signature field to the `PerasVote blk` data type (analogous to the `pvSignature` field already present in `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`).
2. Implement `validatePerasVote` to verify the vote signature against the voter's registered public key, as already done in the `EveryoneVotes` and `WFALS` committee implementations (`implVerifyVote` in `Committee/EveryoneVotes.hs` and `Committee/WFALS.hs`).
3. Implement `validatePerasCert` to verify the aggregate BLS signature, as already done in `implVerifyCert` in those same modules.
4. Remove or gate the degenerate universal instance so it cannot be used in production paths; require an explicit, cryptographically complete instance for each concrete block type.

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to the node's ObjectDiffusion mini-protocol for Peras votes.
2. Peer sends a batch of `PerasVote` messages, each with `pvVoteVoterId` set to a different registered stake pool key hash (public information), `pvVoteRound` set to the current round, and `pvVoteBlock` set to the attacker's target block.
3. `processVotes` in `ObjectPool/PerasVote.hs` calls `validatePerasVote mkPerasParams sd vote` for each vote.
4. `validatePerasVote` (the degenerate instance) calls `lookupPerasVoteStake vote stakeDistr`, which succeeds because the voter IDs are real registered pools.
5. All votes are accepted as `ValidatedPerasVote` and added to the `PerasVoteDB`.
6. Once total stake exceeds the quorum threshold, `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a `ValidatedPerasCert` boosting the attacker's chosen block.
7. The certificate is propagated to the `ChainDB`, where the Peras boost weight causes the node to prefer the attacker's block in chain selection.

**Root cause lines:** [1](#0-0) 

**`validatePerasCert` unconditional acceptance:** [2](#0-1) 

**`validatePerasVote` stake-only check (no signature):** [3](#0-2) 

**Production inbound vote processing entry point:** [4](#0-3) 

**`processVotes` calling the deficient validator:** [5](#0-4) 

**Acknowledged TODO in `PerasVoteDB` implementation:** [6](#0-5) 

**Contrast: correct signature verification in `EveryoneVotes` committee:** [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
