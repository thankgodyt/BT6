### Title
`validatePerasVote` Stub Accepts Votes Without Signature or Round Validation, Enabling Unauthorized Peras Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasVote` as a stub that only checks stake-distribution membership, without verifying any cryptographic proof or round-number validity. An unprivileged peer can forge votes attributed to any registered stake pool operator for any round number — including future rounds where voting power is undefined — causing unauthorized Peras certificates to be generated and accepted, directly analogous to the `_blockNumber > block.number` oversight in the reference report.

### Finding Description

The universal `BlockSupportsPeras` instance at lines 320–389 of `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` provides the only concrete implementation of `validatePerasVote` for all block types:

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

The `_params` argument is discarded entirely. The only check performed is whether the `pvVoteVoterId` field of the incoming vote appears in the `PerasVoteStakeDistr` map. The implementation does **not** verify:

1. Any cryptographic signature or VRF/KES eligibility proof for the claimed voter.
2. That the vote's round number (`pvVoteRound`) corresponds to the current or a past round — votes for future rounds, where the committee and voting power are undefined, are silently accepted.
3. That the voted-on block (`pvVoteBlock`) exists on any known chain.

The same file also provides a `validatePerasCert` stub that unconditionally returns `Right` for every certificate, accepting it with the configured boost weight without any validation whatsoever. [1](#0-0) 

These stubs are wired into the live production inbound-vote processing path. `processVotes` in `PerasVote.hs` calls the injected `validateVote` callback for every peer-supplied vote; both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` supply `validatePerasVote mkPerasParams sd vote` as that callback: [2](#0-1) [3](#0-2) [4](#0-3) 

Once a batch of votes passes `validatePerasVote`, each vote is timestamped and forwarded to `PerasVoteDB.addVote` / `ChainDB.addPerasVoteWithAsyncCertHandling`, which runs `updatePerasRoundVoteStates` and forges a `ValidatedPerasCert` as soon as the accumulated stake crosses the quorum threshold. [5](#0-4) 

The `PerasVoterId` type is a `KeyHash StakePool` — a public key hash that is visible on-chain to every participant. No private key material is required to construct a `PerasVote` carrying a legitimate voter ID. [6](#0-5) [7](#0-6) 

### Impact Explanation

An attacker who knows the public key hashes of registered stake pool operators (universally available from the ledger) can craft `PerasVote` messages for any round number — including future rounds where the committee has not yet been determined and voting power is undefined — and have them accepted as valid. By sending enough forged votes across multiple voter IDs to exceed the quorum threshold, the attacker causes the node to forge a `ValidatedPerasCert` for an attacker-chosen block. That certificate is then used to boost that block's weight in chain selection, potentially causing honest nodes to prefer a non-canonical or adversarially chosen chain. This is a direct bypass of Peras voting and certificate checks enabling unauthorized certificate acceptance, matching the "Critical" tier of the allowed impact scope.

### Likelihood Explanation

Medium. Peras is under active development and is enabled on private testnets (the `eraPerasRoundLength` field already carries a `PerasEnabled` variant). The vulnerable code path (`processVotes` → `makePerasVotePoolWriterFromChainDB`) is production code, not gated behind a feature flag at the call site. The attack requires only knowledge of stake pool key hashes, which are public, and the ability to connect to a node running a Peras-enabled configuration — both achievable by an unprivileged peer on a private testnet.

### Recommendation

Replace the stub `validatePerasVote` implementation with one that:

1. Verifies the cryptographic eligibility proof (VRF output or committee-selection witness) attached to the vote, confirming the claimed voter was actually selected for the claimed round.
2. Rejects votes whose `pvVoteRound` exceeds the current round (analogous to the `_blockNumber > block.number` guard in the reference report), since the committee and voting power for future rounds are undefined.
3. Verifies that `pvVoteBlock` refers to a block that exists on a known chain and satisfies the Peras candidate-block rules.

The same corrections apply to `validatePerasCert`, which currently accepts every certificate unconditionally.

### Proof of Concept

1. Enumerate registered stake pool key hashes from the public ledger state; these are valid `PerasVoterId` values.
2. Construct `PerasVote { pvVoteRound = <any round, including future>, pvVoteBlock = <target block point>, pvVoteVoterId = <harvested key hash> }` for each of several voter IDs whose combined stake exceeds the quorum threshold.
3. Send the batch to a Peras-enabled node via the Peras vote diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each vote; `lookupPerasVoteStake` finds the voter ID in the distribution and returns `Right`.
5. All votes are forwarded to `implAddVote`, which calls `updatePerasRoundVoteStates`; once cumulative stake crosses the quorum threshold, `forgePerasCert` is invoked and a `ValidatedPerasCert` is stored for the attacker-chosen block.
6. The certificate boosts that block's weight in chain selection, causing the node to prefer the attacker-designated chain — a consensus safety failure triggered entirely by crafted network messages from an unprivileged peer, with no private key material required.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L129-134)
```haskell
newtype PerasVoterId = PerasVoterId
  { unPerasVoterId :: KeyHash StakePool
  }
  deriving newtype NoThunks
  deriving stock (Eq, Ord, Generic)
  deriving Show via Quiet PerasVoterId
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-113)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-237)
```haskell
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

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr

```
