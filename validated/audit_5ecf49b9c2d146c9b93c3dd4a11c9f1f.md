### Title
Peras Vote Signature Verification Bypass Allows Unprivileged Peer to Forge Quorum Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation is a stub that performs no cryptographic signature verification. Any unprivileged peer can craft `PerasVote` messages claiming to be any voter present in the stake distribution. These votes pass validation, accumulate in the `PerasVoteDB`, and — once enough are submitted — trigger automatic certificate forging for an attacker-chosen block. The resulting certificate then influences chain selection via Peras weight boosting.

---

### Finding Description

`BlockSupportsPeras` defines the universal instance used for all block types. Its `validatePerasVote` implementation is explicitly marked as a stub:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The only check performed is a stake-distribution membership lookup on `pvVoteVoterId`. No cryptographic signature over the vote body (`pvVoteRound`, `pvVoteBlock`) is verified. The `PerasVote` data type carries no signature field at all in this instance:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

The inbound processing pipeline in `processVotes` calls this stub directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

Votes that pass this check are timestamped and forwarded to `implAddVote`, which deduplicates only by `PerasVoteId = (roundNo, voterId)`. A new `(roundNo, voterId)` pair is unconditionally inserted into `pvdsVoteIds` and counted toward quorum via `updatePerasRoundVoteStates`. When the accumulated stake crosses the quorum threshold, `forgePerasCert` is called automatically — also a stub that always succeeds — producing a `ValidatedPerasCert` that is then stored in `PerasCertDB` and used to boost the target block in chain selection.

The `validatePerasCert` stub similarly accepts every certificate unconditionally:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

---

### Impact Explanation

An unprivileged peer can:

1. Enumerate any set of `PerasVoterId` values present in the current `PerasVoteStakeDistr` (these are public stake pool key hashes).
2. Craft `PerasVote` messages for those voter IDs, all targeting an attacker-chosen block in a chosen round.
3. Submit them via the Peras vote diffusion mini-protocol.
4. Once the accumulated stake of the crafted votes exceeds the quorum threshold, the node automatically forges a `ValidatedPerasCert` for the attacker-chosen block.
5. The certificate is stored in `PerasCertDB` and its `vpcCertBoost` weight is applied during chain selection, causing the node to prefer the boosted (attacker-chosen) chain over the honest canonical chain.

This is a complete bypass of Peras voting authorization: the protocol's security assumption — that only legitimate stake pool operators can cast votes — is entirely absent from the implementation.

---

### Likelihood Explanation

The attack requires only knowledge of current stake pool key hashes (publicly available on-chain) and the ability to connect to a node and send Peras vote messages. No key material, operator access, or stake majority is needed. The Peras vote diffusion mini-protocol is an externally reachable network endpoint. The stub is the universal instance for all block types with no overriding production implementation.

---

### Recommendation

Implement cryptographic signature verification in `validatePerasVote`. The `PerasVote` data type must carry a voter signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)`, and `validatePerasVote` must verify this signature against the voter's registered verification key before accepting the vote. The `WFALS` committee implementation in `implVerifyVote` demonstrates the correct pattern: `checkVoteSignature` / `verifyVoteSignature` must be called before accepting any vote. Until this is implemented, the Peras voting subsystem provides no authorization guarantees.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects and sends a batch of crafted `PerasVote` objects via the Peras vote diffusion mini-protocol.
2. `makePerasVotePoolWriterFromChainDB` → `processVotes` is invoked.
3. `alreadyInDb` check passes (votes are new).
4. `validatePerasVote mkPerasParams sd vote` is called — only checks `Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr sd)`.
5. Votes with any known `PerasVoterId` pass and are forwarded to `ChainDB.addPerasVoteWithAsyncCertHandling`.
6. `implAddVote` inserts each vote; `updatePerasRoundVoteStates` accumulates stake.
7. When stake ≥ quorum threshold, `forgePerasCert` is called, producing a `ValidatedPerasCert` for the attacker-chosen block.
8. `implAddCert` stores the certificate; `getWeightSnapshot` returns the boosted weight; chain selection prefers the attacker-chosen chain.

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
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
