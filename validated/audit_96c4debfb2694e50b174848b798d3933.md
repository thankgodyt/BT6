### Title
Missing Epoch-Snapshot Anchoring and Cryptographic Signature Verification in Peras Vote Validation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` default instance in `BlockSupportsPeras` does not verify any cryptographic signature on incoming Peras votes, and the `PerasVoteStakeDistr` supplied to it is a live, non-epoch-anchored STM read with no snapshot binding to the round or epoch of the vote. This is the direct analog of M-06: voting power is evaluated against mutable current state rather than a checkpointed snapshot for the specific round/epoch, and the authorization check itself is structurally absent.

---

### Finding Description

**Root cause 1 — No cryptographic signature check in `validatePerasVote`**

The default `BlockSupportsPeras` instance (the only concrete instance in the codebase) implements `validatePerasVote` as a pure stake-map lookup with no signature verification:

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

`lookupPerasVoteStake` only checks whether `pvVoteVoterId vote` is a key in the `PerasVoteStakeDistr` map. No VRF proof, no BLS/Ed25519 vote signature, and no eligibility proof is verified. Any peer that knows a pool ID present in the distribution can forge a `PerasVote` for that pool and have it accepted as valid.

**Root cause 2 — `PerasVoteStakeDistr` is a live, non-snapshotted STM read**

`makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB` both accept the stake distribution as `STM m PerasVoteStakeDistr` — a live, mutable action evaluated at the moment of validation, with no binding to the epoch or round of the vote being validated:

```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwAddObjects = \votes ->
        processVotes
          ...
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          ...
    }
```

There is no check that the stake distribution corresponds to the epoch in which `pvVoteRound` falls. A pool operator could cast a vote in round R (epoch E), then redelegate or transfer stake before the vote is validated, causing the validation to use a different stake value than the one that was correct at epoch E. This is the direct analog of M-06's missing `getPriorVotingPower` checkpoint.

**Current production wiring**

In the production node-to-node handler, the stake distribution is currently hardcoded as `pure (PerasVoteStakeDistr mempty)`:

```haskell
makePerasVotePoolWriterFromChainDB
  systemTime
  -- TODO: when actual plumbing for Peras is ready, we will have to
  -- extract the committee selection data from the chainDB to pass
  -- it here, instead of relying on an empty the stake distribution.
  --
  -- Note that the empty stake distribution will cause all votes to
  -- be considered invalid.
  (pure (PerasVoteStakeDistr mempty))
  getChainDB
```

This placeholder causes all inbound votes to fail validation today. However, the design flaw is embedded in the production validation path that will be activated when the plumbing is completed: the `validatePerasVote` interface accepts a live STM distribution with no epoch anchoring, and the implementation performs no signature check.

---

### Impact Explanation

When the Peras stake distribution plumbing is wired up (replacing `pure (PerasVoteStakeDistr mempty)` with a real distribution), an unprivileged peer can:

1. **Forge votes for any pool ID in the distribution** without possessing the pool's private key, because `validatePerasVote` performs no signature verification. A peer that observes the current `PerasVoteStakeDistr` (e.g., via a state query) can construct `PerasVote` messages for high-stake pools and have them accepted.

2. **Manipulate quorum calculations across epoch boundaries** by exploiting the non-snapshotted stake distribution. A pool operator can cast a vote in round R (epoch E), then redelegate stake before the vote is processed, causing the validated `vpvVoteStake` to reflect a different value than the epoch-E snapshot. This can push a target above or below the quorum threshold depending on the direction of the stake change.

Both paths lead to **unauthorized Peras certificate acceptance**: a `ValidatedPerasVotesWithQuorum` is constructed from forged or stake-manipulated votes, `forgePerasCert` produces a `ValidatedPerasCert`, and the ChainDB applies the Peras boost to the wrong block, corrupting chain selection.

---

### Likelihood Explanation

The attack requires the Peras vote diffusion mini-protocol to be active with a non-empty stake distribution — a condition that is explicitly planned and tracked (the TODO references `https://github.com/tweag/cardano-peras/issues/97` and related issues). The entry path (inbound Peras vote diffusion client) is already wired into the production node-to-node handler. No privileged access, key compromise, or stake majority is required: the attacker only needs to know a pool ID present in the distribution, which is public on-chain information.

---

### Recommendation

1. **Add cryptographic signature verification to `validatePerasVote`**: The `PerasVote` type must carry a vote signature (as in the WFALS scheme's `WFALSPersistentVote`/`WFALSNonPersistentVote`), and `validatePerasVote` must verify it against the pool's registered verification key before accepting the vote.

2. **Anchor `PerasVoteStakeDistr` to the epoch of the vote's round**: Replace the live `STM m PerasVoteStakeDistr` with an epoch-indexed snapshot lookup. The stake distribution used to validate a vote for round R must be the snapshot taken at the epoch boundary that governs round R (analogous to how Praos uses `ssStakeMarkPoolDistr` from two epochs prior). This prevents stake manipulation between vote casting and validation.

3. **Enforce round-to-epoch binding in `validatePerasVote`**: The validator should reject any vote whose `pvVoteRound` does not fall within the epoch for which the supplied stake distribution snapshot was taken.

---

### Proof of Concept

**Signature bypass (root cause 1):**

```
1. Attacker queries the node's state to obtain the current PerasVoteStakeDistr,
   identifying pool P with high stake.
2. Attacker constructs PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = P }
   without possessing pool P's private key.
3. Attacker sends this vote via the Peras vote diffusion mini-protocol.
4. makePerasVotePoolWriterFromChainDB calls:
     validatePerasVote mkPerasParams sd vote
   which calls lookupPerasVoteStake, finds P in sd, and returns Right (ValidatedPerasVote ...).
5. The forged vote is added to the ChainDB with pool P's full stake weight.
6. Repeating for enough pools causes votesReachQuorum to return Just ...,
   forgePerasCert produces a ValidatedPerasCert, and the ChainDB boosts block B.
```

**Non-snapshotted stake (root cause 2, direct M-06 analog):**

```
1. Pool P holds 10% stake in epoch E. Round R falls in epoch E.
2. Pool P casts a valid vote for block B in round R.
3. Before the vote is processed, pool P redelegates, dropping to 1% stake.
4. getStakeDistrSTM returns the live distribution reflecting 1% stake.
5. validatePerasVote assigns vpvVoteStake = 1%, not the epoch-E value of 10%.
6. The quorum calculation uses the wrong stake, potentially preventing a valid
   certificate from being forged (or, in the opposite direction, inflating stake
   by redelegating to a larger pool before validation).
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-152)
```haskell
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```
