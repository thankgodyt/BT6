### Title
Peras Vote Signature Verification Bypass Allows Unauthorized Quorum Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` implementation is a stub that only checks whether a voter ID exists in the stake distribution. It performs **no BLS signature verification**. Any unprivileged peer can craft a `PerasVote` with an arbitrary valid pool ID and a fake signature, have it accepted as a `ValidatedPerasVote`, and contribute that pool's full stake weight toward quorum. Combined with the equally stubbed `validatePerasCert` (which unconditionally returns `Right`), an attacker can force a node to forge and accept a Peras certificate for any block of their choosing.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that converts an untrusted network `PerasVote` into a `ValidatedPerasVote` carrying a stake weight. The universal production instance reads:

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

The `_params` argument (which would carry the BLS verification context) is discarded. The only check is `lookupPerasVoteStake`, which is a plain `Map.lookup` on the voter ID:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
```

No BLS signature over `(roundNo, boostedBlock)` is ever verified. The `pvSignature` field of the concrete `PerasVote` wire type is completely ignored.

The same stub pattern applies to `validatePerasCert`, which unconditionally accepts every certificate:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

These stubs are the implementations called in the live vote-ingestion path. `processVotes` in `PerasVote.hs` calls `validatePerasVote mkPerasParams sd vote` for every inbound vote received from a peer, then passes the result directly to `PerasVoteDB.addVote` / `ChainDB.addPerasVoteWithAsyncCertHandling`.

---

### Impact Explanation

A Peras certificate boosts the chain-selection weight of the certified block by `perasWeight`. An attacker who can forge a certificate for a block of their choice can make honest nodes prefer that block over the canonical chain, causing a **chain-selection safety failure**.

The attack proceeds as follows:

1. The attacker enumerates pool IDs from the public stake distribution (available on-chain).
2. For each pool, the attacker crafts a `PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock, pvVoteVoterId = poolId, pvSignature = garbage }`.
3. Each crafted vote passes `validatePerasVote` because `lookupPerasVoteStake` only checks the map key.
4. The votes are added to `PerasVoteDB` and their stake is accumulated in `updateTargetVoteTally`.
5. Once the accumulated stake exceeds the quorum threshold, `votesReachQuorum` returns `Just`, `forgePerasCert` is called, and a `ValidatedPerasCert` is produced for `attackerBlock`.
6. This certificate is then handled by `ChainDB.addPerasVoteWithAsyncCertHandling`, boosting `attackerBlock` in chain selection.

The `validatePerasCert` stub means that even if a certificate arrives directly over the network (rather than being locally forged), it is accepted unconditionally.

**Impact class:** Critical — bypass of vote/certificate signature validation enabling unauthorized certificate acceptance and chain-selection divergence.

---

### Likelihood Explanation

The entry point is the standard Peras object-diffusion mini-protocol, reachable by any peer that can connect to the node. No special privileges, keys, or stake are required. The attacker only needs to know pool IDs from the public stake distribution. The stub is the **only** implementation of `validatePerasVote` for all block types (the `instance StandardHash blk => BlockSupportsPeras blk` catch-all), so there is no code path that performs real verification in the production vote-ingestion pipeline.

---

### Recommendation

1. Replace the stub `validatePerasVote` with a real implementation that verifies the BLS vote signature against the voter's public key from the committee selection context before accepting the vote.
2. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature and, for non-persistent voters, the VRF eligibility proofs.
3. Until real validation is in place, the node should not be deployed in any environment where Peras vote diffusion is active.
4. Track the referenced issue (`cardano-peras/issues/120`) to completion before enabling Peras on any network.

---

### Proof of Concept

An attacker connected to a node via the Peras object-diffusion mini-protocol sends a batch of crafted votes:

```
-- For each poolId in the public stake distribution:
craftedVote = PerasVote
  { pvVoteRound    = currentRound
  , pvVoteBlock    = attackerChosenBlock   -- any block hash
  , pvVoteVoterId  = poolId               -- from public ledger
  , pvSignature    = zeroBLSSignature     -- never checked
  }
```

`processVotes` filters out already-seen vote IDs, then calls `validatePerasVote mkPerasParams sd craftedVote`. Because `lookupPerasVoteStake craftedVote sd` succeeds (the pool ID is in the distribution), the vote is accepted as `ValidatedPerasVote { vpvVoteStake = poolStake }`. After enough pools' stakes are accumulated, `votesReachQuorum` fires, `forgePerasCert` produces a `ValidatedPerasCert` for `attackerChosenBlock`, and the ChainDB boosts that block's chain-selection weight — without any legitimate voter having signed anything.

---

**Root cause files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L195-203)
```haskell
-- | Lookup the stake of a vote cast by a member of a given stake distribution.
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
