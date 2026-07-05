### Title
Missing Vote Signature Verification in `validatePerasVote` Enables Unauthorized Peras Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production catch-all instance of `validatePerasVote` in `SupportsPeras.hs` performs no cryptographic signature verification. An unprivileged peer can forge valid-looking `PerasVote` objects for any voter present in the stake distribution, causing the node to accept them, accumulate fraudulent stake, reach quorum, and forge a `ValidatedPerasCert` boosting an attacker-chosen block — directly corrupting Peras chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasVote` as the gate that must authenticate inbound votes before they enter the vote aggregation pipeline. The only instance present in the repository is the degenerate catch-all:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

The function ignores `_params` entirely and only calls `lookupPerasVoteStake`, which is a plain `Map.lookup` on the voter's key hash:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [2](#0-1) 

No signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)` is checked. No VRF eligibility proof is verified. No round-currency check is performed. Any peer that knows a valid `PerasVoterId` (a `KeyHash StakePool`, which is public ledger data) can construct a `PerasVote` for that voter and have it accepted.

This `validatePerasVote` is the validator wired into both production pool writers:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) 

`processVotes` then passes every vote that clears this non-check directly to `addVote`:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  ...
  ([], validatedVotes) ->
    mapM_ (addVote . WithArrivalTime now) validatedVotes
``` [4](#0-3) 

Once inside `implAddVote`, the vote is passed to `updatePerasRoundVoteStates`, which accumulates stake and forges a certificate the moment the quorum threshold is crossed:

```haskell
case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
  Right (VoteGeneratedNewCert cert, ...) ->
    pure (AddedPerasVoteAndGeneratedNewCert cert, ...)
``` [5](#0-4) 

The deduplication guard in `implAddVote` only prevents the same `(roundNo, voterId)` pair from being counted twice:

```haskell
| Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
| otherwise = tryAddVote pvds voteId
``` [6](#0-5) 

Because the stake distribution is public, an attacker can enumerate all `PerasVoterId` values, forge one vote per voter per round for a chosen block, and submit them across multiple connections. Each forged vote passes `validatePerasVote`, passes the `(roundNo, voterId)` deduplication check (each voter ID is distinct), and accumulates its full ledger stake toward quorum. Once the quorum threshold is crossed, `updateCandidateVoteState` calls `forgePerasCert` and a `ValidatedPerasCert` is produced for the attacker's chosen block.

The structural parallel to the external report is exact: the external bug lets one malicious archiver occupy many slots in the archiver list under different public keys (bypassing IP/port uniqueness), dominating random selection. Here, one malicious peer occupies many slots in the vote tally under different voter IDs (bypassing signature authenticity), dominating quorum calculation.

---

### Impact Explanation

A `ValidatedPerasCert` produced this way carries a `vpcCertBoost` equal to `perasWeight params` and is stored in the `PerasVoteDB` and propagated via `ChainDB.addPerasVoteWithAsyncCertHandling`. The Peras chain selection rule uses certificate boosts to prefer certified chains over uncertified ones. An attacker-forged certificate for a minority or invalid block causes honest nodes to prefer that block, breaking consensus safety. This is a direct bypass of Peras voting checks enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The stake distribution (`PerasVoteStakeDistr`) is derived from public ledger state. All `PerasVoterId` values (stake pool key hashes) are publicly enumerable from the ledger. The `PerasVote` type carries no field that requires knowledge of a private key under the current degenerate instance. The ObjectDiffusion miniprotocol is reachable by any peer that can establish a node-to-node connection. No special privilege is required.

---

### Recommendation

The `validatePerasVote` implementation must verify the cryptographic signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)` using the voter's registered public key before accepting the vote. For the WFALS committee scheme, this means calling `implVerifyVote` (which already performs signature and VRF eligibility checks) as part of vote validation, not only at certificate verification time. The degenerate catch-all instance should be removed or replaced with a compile-time error to prevent it from silently serving as the production validator.

---

### Proof of Concept

1. Obtain the current `PerasVoteStakeDistr` from the node's ledger state (public data).
2. For each `PerasVoterId` in the distribution, construct a `PerasVote`:
   ```
   PerasVote { pvVoteRound = <current round>
             , pvVoteBlock = <attacker-chosen block point>
             , pvVoteVoterId = <voter id from distribution> }
   ```
3. Send these votes to a target node via the ObjectDiffusion miniprotocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each; each returns `Right (ValidatedPerasVote { vpvVoteStake = <voter's stake> })` because the voter ID is present in the distribution.
5. Each vote is passed to `addVote`; `implAddVote` accepts each (distinct `(roundNo, voterId)` pairs).
6. `updatePerasRoundVoteStates` accumulates stake; once `stakeAboveThreshold` is satisfied, `forgePerasCert` is called and a `ValidatedPerasCert` for the attacker's block is stored and propagated.
7. Honest nodes receiving this certificate apply the Peras boost to the attacker's block, preferring it over the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
```
