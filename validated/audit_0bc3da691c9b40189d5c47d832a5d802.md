### Title
Unprivileged Peer Can Pre-occupy Legitimate Voter Slots in `PerasVoteDB`, Suppressing Honest Votes and Enabling False Quorum - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs`)

---

### Summary

An unprivileged peer can submit Peras votes attributed to any legitimate voter ID because `validatePerasVote` is a stub that always returns `Right` with no signature or eligibility verification. The `PerasVoteDB` uses `PerasVoteId = (voterId, roundNo)` as the unique vote key and silently ignores any subsequent vote with the same key. An attacker who sends a forged vote for a legitimate voter before that voter's honest vote arrives permanently suppresses the honest vote for the round. By repeating this for enough committee members, the attacker can prevent honest quorum from being reached or forge a quorum for an adversarial block, bypassing Peras voting and certificate checks.

---

### Finding Description

**Root cause 1 — stub vote validation always accepts any vote:**

`validatePerasVote` in the degenerate `BlockSupportsPeras` instance is explicitly a TODO stub that unconditionally returns `Right`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
``` [1](#0-0) 

This is the instance used in production via `processVotes`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [2](#0-1) 

No voter identity, signature, or committee eligibility is checked. Any peer can submit a `PerasVote` with any `pvVoteVoterId` and it will pass.

**Root cause 2 — first-writer-wins on `(voterId, roundNo)` with silent discard:**

`implAddVote` uses `PerasVoteId = (voterId, roundNo)` as the unique key. If a vote with that key is already present, the new vote is silently discarded:

```haskell
addOrIgnoreVote pvds voteId
  -- Vote is already in the DB => ignore it
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  -- New vote => try to add it to the DB
  | otherwise = tryAddVote pvds voteId
``` [3](#0-2) 

The model explicitly documents the assumption that is violated by this attack:

```
-- NOTE: this is under the assumption that a voter doesn't cast two different
-- votes for the same round (that is, with the same ID but different body).
``` [4](#0-3) 

The `implAddVote` function itself carries a TODO acknowledging missing validation:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
``` [5](#0-4) 

**Attacker-controlled entry path:**

Any peer can send votes via the object diffusion miniprotocol. `processVotes` is the inbound handler:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
``` [6](#0-5) 

The filter only skips votes whose ID is **already** in the DB. An attacker who sends their forged vote first is not filtered. The legitimate voter's subsequent honest vote is then filtered out as a duplicate.

**Attack sequence:**

1. Attacker connects via the node-to-node object diffusion miniprotocol.
2. For each target committee member `V_i` in round `R`, attacker crafts `PerasVote { pvVoteRound = R, pvVoteBlock = adversarial_block, pvVoteVoterId = V_i }`.
3. `processVotes` calls `validatePerasVote` — stub returns `Right` unconditionally.
4. Each forged vote is stored in `PerasVoteDB` under key `(V_i, R)`.
5. When `V_i`'s honest vote arrives (same `(V_i, R)` key), `addOrIgnoreVote` returns `PerasVoteAlreadyInDB` and discards it.
6. The attacker's votes accumulate stake for `adversarial_block`. If enough committee members are pre-occupied, `updatePerasRoundVoteStates` reaches quorum and forges a `ValidatedPerasCert` for the adversarial block. [7](#0-6) 

---

### Impact Explanation

**Impact: Critical** — Bypass of Peras voting and certificate checks.

The attacker can:
- **Suppress honest votes**: prevent legitimate committee members' votes from being counted, blocking honest quorum.
- **Forge a false quorum**: by pre-occupying enough voter slots with votes targeting an adversarial block, cause `PerasVoteDB` to forge a `ValidatedPerasCert` for a block that the honest committee did not actually endorse.

A forged Peras certificate causes the node to accept an unauthorized certificate boost for an adversarial chain, directly enabling unauthorized certificate acceptance and materially weakening the Peras finality guarantee. This falls within: *"Critical. Bypass of… Peras voting or certificate checks… that enables unauthorized… vote, or certificate acceptance."* [8](#0-7) 

---

### Likelihood Explanation

**Likelihood: Medium.**

- Eligible voter IDs (`PerasVoterId`) are derived from public stake pool keys and are observable on-chain.
- The attacker only needs a network connection and the ability to send votes slightly before honest voters — no stake, no keys, no special privilege required.
- The stub `validatePerasVote` is in the production code path (not test-only), gated only by a TODO issue.
- The timing window is the entire Peras round duration, which is a protocol parameter (not a tight race).

---

### Recommendation

1. **Implement `validatePerasVote`**: verify the voter's cryptographic signature and committee eligibility before accepting any vote. The stub must be replaced before Peras is enabled on any network. [9](#0-8) 

2. **Detect and reject equivocating votes in `implAddVote`**: when a vote arrives with a `(voterId, roundNo)` key already present but targeting a **different block**, treat it as an equivocation and reject (or penalize) the sender rather than silently discarding it. The current silent discard is the direct analog of M-05's unguarded `create_lock_for`. [10](#0-9) 

3. **Disconnect peers that send equivocating votes**: `processVotes` already throws `PerasVoteInboundException` for invalid votes, causing peer disconnection. Equivocating votes (same ID, different target) should trigger the same path. [11](#0-10) 

---

### Proof of Concept

```
-- Attacker node, connected via object diffusion miniprotocol to victim node
-- Round R is active; committee members V1..Vk are known from the stake distribution

forM_ [V1..Vk] $ \voterId ->
  sendVote PerasVote
    { pvVoteRound   = R
    , pvVoteBlock   = adversarialBlockPoint   -- attacker's chosen block
    , pvVoteVoterId = voterId                 -- legitimate committee member's ID
    }

-- On victim node:
-- processVotes calls validatePerasVote => Right (stub, no signature check)
-- implAddVote stores each vote under key (voterId, R)
-- When V1..Vk send their honest votes for the honest block:
--   addOrIgnoreVote: Set.member (Vi, R) pvdsVoteIds => True => PerasVoteAlreadyInDB
-- Honest votes are silently discarded.
-- Attacker's votes accumulate stake for adversarialBlockPoint.
-- If total stake >= quorum threshold:
--   updatePerasRoundVoteStates => VoteGeneratedNewCert adversarialCert
-- Node now holds a ValidatedPerasCert for the adversarial block.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L299-303)
```haskell
  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-358)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-142)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L154-159)
```haskell
data PerasVoteInboundException
  = forall blk. PerasVoteValidationError [PerasValidationErr blk]

deriving instance Show PerasVoteInboundException

instance Exception PerasVoteInboundException
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-200)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-211)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasVoteDB/Model.hs (L150-152)
```haskell
  --
  -- NOTE: this is under the assumption that a voter doesn't cast two different
  -- votes for the same round (that is, with the same ID but different body).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/API.hs (L81-86)
```haskell
data AddPerasVoteResult blk
  = PerasVoteAlreadyInDB
  | AddedPerasVoteButDidntGenerateNewCert
  | AddedPerasVoteAndGeneratedNewCert (ValidatedPerasCert blk)
  deriving stock (Generic, Eq, Ord, Show)
  deriving anyclass NoThunks
```
