### Title
Incomplete `PerasVoteId` Omits Target Block, Silently Dropping Equivocating Votes and Enabling Peras Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`PerasVoteId` is defined with only `pviRoundNo` and `pviVoterId`, omitting the target block (`pvVoteBlock`). The network inbound handler `processVotes` and the DB layer `implAddVote` both deduplicate votes by this incomplete identifier. As a result, a second vote from the same voter in the same round but targeting a **different block** (an equivocating vote) is silently dropped rather than detected. An adversary controlling a single voter key can exploit this to steer Peras chain-selection boosts toward an adversarial block by racing their preferred vote to all peers before the honest vote arrives.

---

### Finding Description

`PerasVote` carries three fields: round number, target block, and voter ID:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk      -- ← target block
  , pvVoteVoterId :: PerasVoterId
  }
```

`PerasVoteTarget` (used for quorum aggregation) correctly includes both round and block:

```haskell
data PerasVoteTarget blk = PerasVoteTarget
  { pvtRoundNo :: !PerasRoundNo
  , pvtBlock   :: !(Point blk)
  }
```

But `PerasVoteId` (used for deduplication) drops the block entirely:

```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
``` [1](#0-0) 

`getPerasVoteId` projects only round + voter, discarding `pvVoteBlock`:

```haskell
instance HasPerasVoteId (PerasVote blk) blk where
  getPerasVoteId vote =
    PerasVoteId
      { pviRoundNo = pvVoteRound vote
      , pviVoterId = pvVoteVoterId vote
      }
``` [2](#0-1) 

The network inbound handler `processVotes` uses this ID to filter out "already seen" votes:

```haskell
let votesNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
``` [3](#0-2) 

The DB layer `implAddVote` performs the same check:

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
``` [4](#0-3) 

Because `PerasVoteId` does not include the target block, two votes `(round=R, block=B1, voter=V)` and `(round=R, block=B2, voter=V)` share the same ID `(round=R, voter=V)`. The second vote is silently dropped at both the network and DB layers. No equivocation is detected, no peer is disconnected, and the node's quorum accounting is permanently biased toward whichever block arrived first.

---

### Impact Explanation

Peras chain selection works by accumulating vote stake per `(round, block)` target. When a quorum is reached for a target, a certificate is forged and that block receives a weight boost that influences chain selection. [5](#0-4) 

Because equivocating votes are silently dropped, an adversary who controls a voter key can:

1. Send `vote(round=R, block=B_adversary, voter=V)` to all peers first.
2. Send `vote(round=R, block=B_honest, voter=V)` to all peers second.

Every honest node accepts the first vote and silently drops the second. Block `B_adversary` accumulates V's stake toward quorum; `B_honest` does not. If V's stake is sufficient (or combined with other adversarial voters), a certificate is forged for `B_adversary`, boosting it in chain selection and causing honest nodes to prefer the adversarial chain over the canonical one.

This maps to: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

The attack requires controlling a single stake pool operator key that is eligible to vote in a Peras round. This is a legitimate protocol participant acting maliciously — it does not require key compromise, admin access, or a stake majority. The adversary only needs to race their preferred vote to peers before the honest vote, which is achievable by any network-connected adversary with a voter key. Likelihood: **High**.

---

### Recommendation

Include `pvVoteBlock` in `PerasVoteId` so that two votes from the same voter in the same round but for different blocks are treated as distinct objects rather than duplicates:

```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo  :: !PerasRoundNo
  , pviVoterId  :: !PerasVoterId
  , pviVoteBlock :: !(Point blk)   -- add this field
  }
```

Correspondingly update `getPerasVoteId` to project `pvVoteBlock`, and update the `Serialise` / `SerialiseNodeToNode` instances for `PerasVoteId` to encode the block field. [6](#0-5) 

Additionally, `processVotes` should treat a vote whose ID (with block included) is new but whose `(round, voter)` pair already exists as an **equivocation**, log it, and disconnect from the sending peer rather than silently dropping it. [7](#0-6) 

---

### Proof of Concept

**Setup:** Two honest nodes N1 and N2. Voter V has enough stake to tip quorum. Round R is active. Two candidate blocks exist: `B_adv` (adversary's preferred) and `B_honest` (canonical tip).

**Step 1 — Adversary sends equivocating votes:**
```
Adversary → N1: PerasVote { pvVoteRound=R, pvVoteBlock=B_adv,   pvVoteVoterId=V }
Adversary → N2: PerasVote { pvVoteRound=R, pvVoteBlock=B_adv,   pvVoteVoterId=V }
```
Both nodes accept: `getPerasVoteId` → `(R, V)`, not in DB, stored.

**Step 2 — Adversary (or honest relay) sends the honest vote:**
```
Adversary → N1: PerasVote { pvVoteRound=R, pvVoteBlock=B_honest, pvVoteVoterId=V }
Adversary → N2: PerasVote { pvVoteRound=R, pvVoteBlock=B_honest, pvVoteVoterId=V }
```
Both nodes compute `getPerasVoteId` → `(R, V)` — already in `pvdsVoteIds` — and call `voteAlreadyInDB`, silently dropping the vote. [8](#0-7) 

**Result:** V's stake is counted toward `B_adv` on both nodes. If quorum is reached, a certificate is forged for `B_adv`, boosting it in Peras chain selection. `B_honest` receives no boost. Honest nodes switch to the adversarial chain. No equivocation is ever detected, no peer is disconnected. [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L181-193)
```haskell
data PerasVoteTarget blk = PerasVoteTarget
  { pvtRoundNo :: !PerasRoundNo
  , pvtBlock :: !(Point blk)
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks

data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L226-235)
```haskell
data ValidatedPerasVotesWithQuorum blk = ValidatedPerasVotesWithQuorum
  { vpvqTarget :: !(PerasVoteTarget blk)
  -- ^ The target that all the votes are for
  , vpvqVotes :: !(NonEmpty (ValidatedPerasVote blk))
  -- ^ The votes that reached quorum for the given target
  , vpvqPerasCfg :: !(PerasCfg blk)
  -- ^ The Peras configuration used to validate that the votes reach quorum
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L424-433)
```haskell
instance Serialise (PerasVoteId blk) where
  encode PerasVoteId{pviRoundNo, pviVoterId} =
    encodeListLen 2
      <> encode pviRoundNo
      <> KeyHash.toCBOR (unPerasVoterId pviVoterId)
  decode = do
    decodeListLenOf 2
    pviRoundNo <- decode
    pviVoterId <- PerasVoterId <$> KeyHash.fromCBOR
    pure $ PerasVoteId{pviRoundNo, pviVoterId}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L565-570)
```haskell
instance HasPerasVoteId (PerasVote blk) blk where
  getPerasVoteId vote =
    PerasVoteId
      { pviRoundNo = pvVoteRound vote
      , pviVoterId = pvVoteVoterId vote
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-170)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
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
