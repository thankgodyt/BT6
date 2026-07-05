### Title
Peras Vote Signature and Certificate Verification Bypass Enables Unauthorized Quorum and Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used by all block types provides stub implementations of `validatePerasVote` and `validatePerasCert` that perform no cryptographic verification. An unprivileged peer can send crafted votes bearing any legitimate stake-pool voter ID, bypass all signature and eligibility checks, accumulate fabricated stake toward quorum, and cause the local node to forge and accept a Peras certificate for an attacker-chosen block — directly affecting chain selection. Separately, `validatePerasCert` accepts every inbound certificate unconditionally, allowing a single crafted message to inject a certificate for any round and any block.

---

### Finding Description

**Root cause 1 — `validatePerasVote` performs no cryptographic check.**

The catch-all `BlockSupportsPeras` instance (the only instance in the repository) implements `validatePerasVote` as:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

The only check is whether `pvVoteVoterId` appears in the `PerasVoteStakeDistr` map. The BLS signature (`pvSignature`), the VRF eligibility proof (`pvEligibilityProof`), the round number, and the boosted block are all ignored. A peer can therefore craft a `PerasVote` with any voter ID present in the public stake distribution, any round number, and any target block, and the vote will be accepted as fully validated.

**Root cause 2 — `validatePerasCert` is unconditional.**

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

Every inbound certificate is accepted regardless of its content.

**Inbound processing path.**

`processVotes` (the production inbound handler) reads the current `pvdsVoteIds` set in a single STM transaction, filters out already-known vote IDs, then calls `validatePerasVote` on the remainder:

```haskell
validationResults <- atomically $ do
  alreadyInDb <- alreadyInDbSTM
  let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
  mapM validateVote votesNotAlreadyInDb
``` [3](#0-2) 

Because `validatePerasVote` only checks stake-distribution membership, every forged vote for a known voter ID passes. The same pattern applies to `processCerts`: [4](#0-3) 

**Deduplication does not prevent the attack.**

`implAddVote` deduplicates by `PerasVoteId = (roundNo, voterId)`:

```haskell
| Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
| otherwise = tryAddVote pvds voteId
``` [5](#0-4) 

This prevents the same `(roundNo, voterId)` pair from being inserted twice, but it does not prevent an attacker from submitting one forged vote per distinct voter ID in the stake distribution. The `PerasVoteStakeDistr` is public; an attacker can enumerate all pool IDs and craft one vote per pool.

**Stake accumulation toward quorum.**

`updateTargetVoteTally` accumulates `vpvVoteStake` per unique `PerasVoteId`:

```haskell
| (Nothing, votes') <- swapVote vote ptvtVotes =
    (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
``` [6](#0-5) 

Once the accumulated stake exceeds the quorum threshold, `updateCandidateVoteState` calls `forgePerasCert` and a certificate is produced: [7](#0-6) 

**Chain selection impact.**

The forged certificate is consumed by `getPerasWeightSnapshot` and used in `readChainComparison` to compute `compareCandidateChains`, directly influencing which candidate chain the node adopts: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer connected via the Peras object-diffusion mini-protocol can:

1. **Vote-based path**: Send one forged `PerasVote` per stake-pool ID in the public distribution, all targeting the same `(roundNo, block)`. Because `validatePerasVote` only checks stake-distribution membership, each vote is accepted. Once accumulated stake exceeds the quorum threshold, the node locally forges a `ValidatedPerasCert` for the attacker-chosen block. This certificate boosts that block in chain selection, potentially causing the node to prefer a non-canonical or adversarially chosen chain.

2. **Direct cert path**: Send a single crafted `PerasCert` for any round not yet in the DB. Because `validatePerasCert` returns `Right` unconditionally, the certificate is accepted immediately without any votes.

Both paths constitute a **bypass of Peras certificate/vote verification** that enables unauthorized certificate acceptance and chain-selection manipulation. This matches the "High" impact category: bypass of certificate/signature validation that enables unauthorized certificate acceptance.

---

### Likelihood Explanation

The attack is reachable by any peer that can connect to the node's Peras object-diffusion endpoint. The stake distribution (`PerasVoteStakeDistr`) is public. Constructing a `PerasVote` requires only a `PerasRoundNo`, a `Point blk`, and a `PerasVoterId` — all of which are observable on-chain. No key material, admin access, or stake majority is required. The `TODO` comments and referenced issues (`#120`, `#73`) confirm the stubs are present in the current production codebase. [9](#0-8) [10](#0-9) 

---

### Recommendation

1. **`validatePerasVote`**: Implement full cryptographic validation — verify the BLS signature against the voter's public key, verify the VRF eligibility proof (for non-persistent committee members), and check that the round number and boosted block are within the valid window for the current slot.

2. **`validatePerasCert`**: Implement certificate validation — verify the aggregate BLS signature over the claimed set of votes, check that the round number is valid, and confirm the boosted block is known and on a valid chain.

3. Until these are implemented, the Peras object-diffusion inbound handlers (`processVotes`, `processCerts`) should not be exposed to untrusted peers in any deployment where Peras certificates influence chain selection.

---

### Proof of Concept

```
-- Attacker connects to the Peras vote diffusion endpoint.
-- Stake distribution is public; attacker enumerates all pool IDs.
-- For each poolId in stakeDistr, attacker sends:
--
--   PerasVote
--     { pvVoteRound  = targetRound   -- any round not yet decided
--     , pvVoteBlock  = attackerBlock -- attacker-chosen block point
--     , pvVoteVoterId = poolId       -- legitimate pool ID, no key needed
--     }
--
-- processVotes filters by PerasVoteId (roundNo, voterId) — not yet in DB.
-- validatePerasVote checks only: Map.lookup poolId stakeDistr — succeeds.
-- Each vote is inserted; ptvtTotalStake accumulates.
-- Once sum(stake) >= quorumThreshold + safetyMargin:
--   updateCandidateVoteState → forgePerasCert → ValidatedPerasCert forged
--   for attackerBlock in targetRound.
-- Certificate boosts attackerBlock in compareCandidateChains.
-- Node may switch to attacker-chosen chain.
--
-- Alternatively (direct cert injection):
--   Send PerasCert { pcCertRound = targetRound, pcCertBoostedBlock = attackerBlock }
--   processCerts → validatePerasCert → Right (unconditional) → cert accepted.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L453-459)
```haskell
    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-240)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
```
