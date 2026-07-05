### Title
Missing Stake Normalization Invariant in Peras Quorum Check Enables Certificate Quorum Bypass - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares a raw `PerasVoteStake` `Rational` directly against the quorum threshold without enforcing that the vote stake has been normalized to a relative (fractional) value. The code itself acknowledges there is no agreed-upon normalization step. When the production stake-distribution plumbing is connected (replacing the current empty-map placeholder), any registered stake pool whose absolute lovelace stake is stored unnormalized in `PerasVoteStakeDistr` will trivially satisfy the `>= 3/4` quorum check as a single voter, forging a Peras certificate for an arbitrary block without genuine committee consensus.

---

### Finding Description

`PerasVoteStake` is a plain `Rational` newtype. The code comment at its definition explicitly states:

> "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee" [1](#0-0) 

`stakeAboveThreshold` then compares this raw value directly against the quorum threshold (`3/4`) and safety margin (`2/100`) with no normalization guard:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake = unPerasVoteStake voteStake
  ...
```

The function's own TODO documents the missing invariant:

> "this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The production vote-ingest path in `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote` where `sd` is the `PerasVoteStakeDistr` obtained from an STM action. The comment at the call site explicitly marks the stake-distribution wiring as a TODO:

> "when actual plumbing for Peras is ready, we will have to extract the committee selection data from the chainDB to pass it here, instead of relying on an empty the stake distribution." [3](#0-2) 

Currently the placeholder is `pure (PerasVoteStakeDistr mempty)`, so all votes are rejected. However, the `makePerasVotePoolWriterFromChainDB` function already exists and is wired into the live diffusion layer: [4](#0-3) 

When the ChainDB-backed stake distribution is connected, `PerasVoteStakeDistr` will be populated from the ledger's `PoolDistr`, which stores **absolute** lovelace-denominated `individualPoolStake` values. Because `stakeAboveThreshold` performs no normalization, a single voter whose absolute stake entry is any value ≥ 0.77 (i.e., any pool holding ≥ 0.77 lovelace, which is every real pool) will satisfy the quorum check alone.

The quorum check is the gate for `votesReachQuorum`, which is the only guard before `forgePerasCert` is called: [5](#0-4) 

---

### Impact Explanation

A single registered stake pool (unprivileged network peer) can send one `PerasVote` for any block. Because the unnormalized absolute stake value stored in `PerasVoteStakeDistr` will be ≫ 0.77, `stakeAboveThreshold` returns `True` immediately, `votesReachQuorum` succeeds, and `forgePerasCert` produces a `ValidatedPerasCert` boosting the attacker's chosen block by `perasWeight = 15` chain-weight units. This is a bypass of the Peras certificate quorum check — the security property that requires ≥ 3/4 of the committee's stake to agree before a block is boosted. A boosted adversarial block can win chain selection over a longer honest chain, constituting a consensus safety failure.

---

### Likelihood Explanation

The vulnerability is latent: the empty-map placeholder currently prevents exploitation. However, the code is in active development, the stake-distribution wiring is an explicitly planned next step (the TODO comment in `NodeToNode.hs`), and the normalization gap is acknowledged but unresolved at the type level. Once the ChainDB-backed `PerasVoteStakeDistr` is connected without a normalization step, any registered stake pool peer can trigger the bypass with a single crafted vote message over the existing `PerasVoteDiffusion` mini-protocol.

---

### Recommendation

1. **Enforce the invariant at the type boundary.** Replace the raw `Rational` in `PerasVoteStake` with a newtype that can only be constructed via a smart constructor that accepts the total active stake and normalizes the value, e.g. `mkPerasVoteStake :: Coin -> Coin -> PerasVoteStake`.
2. **Normalize inside `stakeAboveThreshold`.** Change the signature to accept the total committee stake and perform the division internally, removing the unit-mismatch risk entirely.
3. **Add a property test** asserting that the sum of all `PerasVoteStake` values in any valid `PerasVoteStakeDistr` is ≤ 1, and that `stakeAboveThreshold` only returns `True` when the normalized fraction exceeds the threshold.

---

### Proof of Concept

Assume the ChainDB-backed distribution is connected and pool `P` has 1,000,000 lovelace absolute stake stored as `PerasVoteStake (1000000 % 1)`:

```
stakeAboveThreshold mkPerasParams (PerasVoteStake (1000000 % 1))
  = (1000000 % 1) >= (3 % 4) + (2 % 100)
  = (1000000 % 1) >= (77 % 100)
  = True   -- quorum declared with one vote
```

Pool `P` sends a single `PerasVote` for block `B` over the `PerasVoteDiffusion` mini-protocol. `processVotes` → `validatePerasVote` → `addPerasVoteWithAsyncCertHandling` → `updateCandidateVoteState` → `votesReachQuorum` → `forgePerasCert` produces a certificate boosting `B` by weight 15, without any other committee member voting. [6](#0-5) [5](#0-4) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-151)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
  deriving stock Generic
  deriving Show via Quiet PerasVoteStake
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L399-408)
```haskell
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
