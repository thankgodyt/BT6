### Title
Stub `validatePerasVote` Accepts Unsigned Crafted Votes, Enabling Fraudulent Quorum Certificate Forging - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` implementation is a stub that only checks whether a voter ID appears in the stake distribution. It performs no signature verification, no VRF eligibility proof check, and no voting-rule enforcement. An unprivileged peer can send crafted `PerasVote` messages with any valid pool ID and any block hash, have them accepted as valid, and — if enough stake is covered — cause the node to forge a fraudulent Peras quorum certificate that boosts a non-canonical chain.

---

### Finding Description

**Vulnerability class (analog):** The external report describes a function that should enforce a per-epoch rate limit but lacks the guard, allowing unlimited accrual of a privileged resource. The analog here is a vote-validation function that should enforce cryptographic correctness (signature, eligibility proof, voting rules) but is a stub that enforces none of them, allowing unlimited injection of fraudulent vote weight.

**Root cause — `validatePerasVote` stub:**

The `BlockSupportsPeras` instance used for all block types is explicitly marked as a degenerate placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [1](#0-0) 

The function accepts any vote whose `pvVoteVoterId` appears in the stake distribution map, regardless of:
- Whether the vote carries a valid cryptographic signature
- Whether a non-persistent committee member has a valid VRF eligibility proof
- Whether the voting rules VR-1A/VR-1B/VR-2A/VR-2B are satisfied
- Whether the voter is actually a committee member for this round

**Production entry path — `processVotes`:**

Inbound votes from peers flow through `processVotes`, which calls `validatePerasVote` inside an STM transaction:

```haskell
validationResults <- atomically $ do
  alreadyInDb <- alreadyInDbSTM
  let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
  mapM validateVote votesNotAlreadyInDb
```

where `validateVote` is:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [2](#0-1) [3](#0-2) 

All votes that pass `validatePerasVote` are then added to the `PerasVoteDB` via `implAddVote`, which calls `updatePerasRoundVoteStates` to accumulate stake toward quorum:

```haskell
case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
  Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
    pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
``` [4](#0-3) 

**Deduplication does not save the node:** The `PerasVoteId` is `(roundNo, voterId)`. The deduplication guard in `implAddVote` correctly prevents the same `(roundNo, voterId)` pair from being counted twice:

```haskell
| Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
``` [5](#0-4) 

However, this only prevents replay of the *same* vote. An attacker can send one crafted vote per pool ID per round — each with a different pool ID from the public stake distribution — and each will be accepted as a distinct, valid vote. With enough pool IDs covered, the attacker accumulates stake above the quorum threshold and a fraudulent certificate is forged.

**Quorum threshold and certificate forging:**

`updateCandidateVoteState` calls `votesReachQuorum` and, if the threshold is exceeded, calls `forgePerasCert`:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [6](#0-5) 

The `forgePerasCert` stub also performs no cryptographic verification:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasForgeErr' variants
forgePerasCert params votes =
  return $ ValidatedPerasCert { vpcCert = ..., vpcCertBoost = perasWeight params }
``` [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can:

1. Enumerate public pool IDs from the stake distribution (public on-chain data).
2. Craft `PerasVote` messages for each pool ID, targeting an arbitrary block in the current round.
3. Send the batch to a victim node via the Peras vote diffusion mini-protocol.
4. Each crafted vote passes `validatePerasVote` (only checks stake distribution membership).
5. Each vote is added to `PerasVoteDB` and its stake is accumulated toward quorum.
6. Once the quorum threshold is exceeded, a `ValidatedPerasCert` is forged for the attacker-chosen block.
7. The certificate boosts the attacker's chosen chain, causing the node to prefer a non-canonical or adversarially-controlled chain.

This is a **Critical** impact: bypass of Peras vote/certificate verification that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

**High.** The attack requires only:
- Network access to a node running the Peras vote diffusion mini-protocol (publicly reachable).
- Knowledge of pool IDs in the stake distribution (fully public on-chain data).
- No cryptographic keys, no stake, no admin access.

The `BlockSupportsPeras` instance is the only instance in the codebase (the `TODO` comment confirms it applies to all block types), so every node running Peras vote diffusion is affected.

---

### Recommendation

1. **Implement real signature verification** in `validatePerasVote` before enabling the Peras vote diffusion mini-protocol in any environment where untrusted peers can connect. The `WFALS` committee's `implVerifyVote` already contains the correct signature and VRF verification logic and should be wired into `validatePerasVote`.

2. **Implement voting rule checks** (VR-1A, VR-1B, VR-2A, VR-2B) in `validatePerasVote` using the `perasVR*` predicates already defined in `Ouroboros.Consensus.Peras.Voting.Rules`.

3. **Gate the Peras vote diffusion mini-protocol** behind a feature flag that is disabled until the stub validation is replaced.

4. **Track the open issue** at `https://github.com/tweag/cardano-peras/issues/120` as a security-critical blocker.

---

### Proof of Concept

A private-testnet sequence demonstrating the issue:

```
-- Setup: node running with Peras vote diffusion enabled, stake distribution known.
-- Attacker connects as a peer and sends crafted votes.

-- For each poolId in stakeDistr (public data):
let craftedVote = PerasVote
      { pvVoteRound  = currentRound        -- current Peras round
      , pvVoteBlock  = attackerChosenBlock  -- any block hash
      , pvVoteVoterId = poolId              -- valid pool ID, no signature needed
      }

-- processVotes calls validatePerasVote for each:
-- validatePerasVote _params stakeDistr craftedVote
--   => lookupPerasVoteStake craftedVote stakeDistr = Just stake  (pool IS in distribution)
--   => Right (ValidatedPerasVote { vpvVoteStake = stake })       (accepted, no sig check)

-- After enough pool IDs are covered:
-- updatePerasRoundVoteStates accumulates stake above quorum threshold
-- => forgePerasCert is called for attackerChosenBlock
-- => ValidatedPerasCert is stored and used to boost attackerChosenBlock
-- => Node's chain selection now prefers the attacker's chain
```

The deduplication guard (`pvdsVoteIds`) only prevents the same `(roundNo, voterId)` pair from being counted twice, so one crafted vote per pool ID per round is sufficient to accumulate the full stake of the distribution.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L373-385)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-212)
```haskell
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
