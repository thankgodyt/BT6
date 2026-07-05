### Title
Peras Vote and Certificate Validation Completely Bypassed — Any Peer Can Forge Votes for Any Registered Pool - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used for all block types omits all cryptographic verification from both `validatePerasVote` and `validatePerasCert`. An unprivileged peer can send crafted `PerasVote` messages claiming to be any registered stake pool, for any block, in any round, and the node will accept them as valid. This is a direct analog of the Krystal DeFi replay/parameter-mismatch bug: just as Krystal verified only that *a* signature existed without checking what was signed or preventing reuse, Ouroboros Consensus verifies only that the voter ID appears in the stake distribution, with no cryptographic proof that the pool actually cast that vote.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` and `validatePerasCert` as the mandatory gatekeepers before votes and certificates affect chain selection. The only concrete instance in the codebase is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` that is used for every block type, including production Cardano blocks.

**`validatePerasVote` — no signature check:**

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

The only check performed is `lookupPerasVoteStake`, which is a plain `Map.lookup` on `pvVoteVoterId`:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

The `PerasVote blk` data type in this instance carries no signature field at all:

```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
```

There is nothing to verify. An attacker constructs a `PerasVote` with any registered pool's `PerasVoterId`, any `pvVoteBlock`, and any `pvVoteRound`, and it passes.

**`validatePerasCert` — unconditional accept:**

```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

Every certificate received over the network is accepted without any check.

**Reachable entry path — inbound vote processing:**

`processVotes` in `PerasVote.hs` is called directly on votes received from peers via the object-diffusion mini-protocol. It calls `validatePerasVote` as the sole gate:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

A vote that passes this call is timestamped and inserted into the `PerasVoteDB` or `ChainDB`, where it participates in quorum accumulation and certificate forging.

---

### Impact Explanation

An unprivileged peer can:

1. **Forge votes for any registered stake pool** — by setting `pvVoteVoterId` to any pool key hash present in the current stake distribution, with no key material required.
2. **Vote for any block in any round** — `pvVoteBlock` and `pvVoteRound` are fully attacker-controlled.
3. **Manufacture quorum** — by sending enough forged votes (each attributed to a different registered pool) to exceed the `perasQuorumStakeThreshold`, triggering `votesReachQuorum` and causing the node to call `forgePerasCert` and boost an attacker-chosen block.
4. **Replay votes across rounds** — since there is no signature binding a vote to a specific round, a vote ID `(roundNo, voterId)` is the only deduplication key; an attacker can submit the same voter ID for a different round with a different block target.

The boosted block receives a `PerasWeight` advantage in chain selection, causing honest nodes to prefer the attacker's chain over the canonical chain. This is a direct Peras voting/certificate check bypass enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The attack requires only network connectivity to a node running Peras. No keys, no stake, no privileged role. The attacker needs only to know the current stake distribution (publicly available on-chain) to enumerate valid voter IDs. The object-diffusion mini-protocol is designed to accept votes from any connected peer, making this trivially reachable.

---

### Recommendation

1. Add a cryptographic signature field to the `PerasVote blk` data type (analogous to `pvSignature` in `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`).
2. Implement `validatePerasVote` to verify the BLS signature over `(pvVoteRound, pvVoteBlock)` using the public key associated with `pvVoteVoterId` in the committee.
3. Implement `validatePerasCert` to verify the aggregate BLS signature over the certificate's election ID and candidate block.
4. Until the full implementation is in place, the degenerate instance should reject all votes and certificates (`Left PerasValidationErr`) rather than accepting them unconditionally, so that the incomplete code path cannot be exploited on a live network.

---

### Proof of Concept

```
-- Attacker constructs a forged vote for pool "PoolX" (any registered pool):
let forgedVote = PerasVote
      { pvVoteRound  = currentRound          -- any round
      , pvVoteBlock  = attackerChosenBlock    -- any block point
      , pvVoteVoterId = PerasVoterId poolXKeyHash  -- any registered pool
      }

-- Send forgedVote to a node via the object-diffusion mini-protocol.
-- processVotes calls:
--   validatePerasVote mkPerasParams stakeDistr forgedVote
-- which calls:
--   lookupPerasVoteStake forgedVote stakeDistr
--   = Map.lookup poolXKeyHash stakeDistrMap
-- This succeeds (poolX is registered), returning Right ValidatedPerasVote.
-- The vote is inserted into the PerasVoteDB with poolX's full stake weight.
-- Repeat for enough pools to exceed quorumStakeThreshold.
-- votesReachQuorum returns Just ValidatedPerasVotesWithQuorum.
-- forgePerasCert produces a ValidatedPerasCert boosting attackerChosenBlock.
-- Chain selection now prefers the attacker's chain.
```

**Root cause lines:** [1](#0-0) 

**No signature field on the vote type:** [2](#0-1) 

**Certificate always accepted:** [3](#0-2) 

**Stake-only lookup used as the sole gate:** [4](#0-3) 

**Reachable entry point from inbound peer votes:** [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
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
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
