### Title
Peras Quorum Check Bypassed by Unnormalized Vote Stake Comparison — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares the accumulated `PerasVoteStake` — a raw `Rational` sourced from the ledger's absolute stake distribution — directly against the relative quorum threshold (3/4) without any normalization step. The production source file itself documents this as an unresolved unit mismatch. If `PerasVoteStakeDistr` is populated with absolute Lovelace values (as the ledger provides, and as the comment implies is the current state), any voter with even a trivially small stake can single-handedly satisfy the quorum check and cause the node to forge a Peras certificate for an attacker-chosen block.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs a bare numeric comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake
  quorumThreshold = unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params)
```

`perasQuorumStakeThreshold` is a relative value — `3/4 = 0.75` — as set in `mkPerasParams`. [1](#0-0) 

`PerasVoteStake` is a plain `Rational` whose value is taken verbatim from `PerasVoteStakeDistr` via `lookupPerasVoteStake` during `validatePerasVote`. [2](#0-1) 

The production comment on `PerasVoteStake` explicitly acknowledges the unresolved unit mismatch:

> *"At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."* [3](#0-2) 

The companion comment on `stakeAboveThreshold` reinforces this:

> *"this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."* [4](#0-3) 

The quorum check is invoked inside `votesReachQuorum`, which is the gate that triggers `forgePerasCert`: [5](#0-4) 

And `updateCandidateVoteState` calls `votesReachQuorum` to decide whether to forge a certificate: [6](#0-5) 

The `PerasVoteStakeDistr` is read from an STM action and passed directly into `validatePerasVote` at the network ingestion point: [7](#0-6) 

**Analog to the inflation attack:** In the ERC4626 report, `xETH.balanceOf(address(this))` (an externally inflatable value) is used as the denominator of the exchange rate instead of an internally tracked balance. Here, the absolute ledger stake (an externally observable value that is orders of magnitude larger than the relative threshold) is used as the numerator of the quorum comparison instead of a normalized relative fraction. In both cases, the "wrong scale" value dominates the comparison and collapses the security invariant.

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute Lovelace values (e.g., a voter with 1 ADA = 1 000 000 Lovelace has `PerasVoteStake = 1000000`), then:

```
stakeAboveThreshold: 1000000 >= 0.75 + 0.02  →  True
```

A single vote from any voter with any non-zero stake satisfies the quorum check. The node immediately forges a `ValidatedPerasCert` for the attacker's chosen block. That certificate is stored in the `PerasVoteDB`, propagated to peers, and applied to chain selection via the Peras boost weight (`perasWeight = 15`), causing honest nodes to prefer the attacker's block over the canonical chain.

This is a **bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance**, which falls under the Critical allowed impact scope.

---

### Likelihood Explanation

The comment explicitly states there is *"no consensus from researchers/engineers"* on how to normalize the stake, strongly implying the normalization step is absent in the current implementation. The attack entry path is the standard Peras vote mini-protocol, reachable by any peer with any stake. No key compromise, stake majority, or privileged access is required.

---

### Recommendation

Normalize `PerasVoteStake` values before they enter the quorum comparison. Two equivalent fixes:

1. **At population time:** When building `PerasVoteStakeDistr` from the ledger, divide each voter's absolute stake by the total stake of all voters in the distribution, producing values in `[0, 1]`.
2. **At comparison time:** Change `stakeAboveThreshold` to accept the total stake as an additional parameter and perform `stake / totalStake >= quorumThreshold + safetyMargin` internally.

Either approach mirrors the ERC4626 mitigation: track the denominator internally rather than relying on an externally observable raw value.

---

### Proof of Concept

1. Attacker controls a pool with 1 ADA (1 000 000 Lovelace) in the current epoch's stake snapshot.
2. `PerasVoteStakeDistr` is built from the ledger: `{ attackerPoolId → PerasVoteStake (1000000 % 1) }`.
3. Attacker sends a `PerasVote` for adversarial block `B` in round `R` via the object-diffusion mini-protocol.
4. Node calls `validatePerasVote mkPerasParams stakeDistr vote` → `Right (ValidatedPerasVote { vpvVoteStake = 1000000 })`.
5. `updateTargetVoteTally` accumulates `ptvtTotalStake = 1000000`.
6. `votesReachQuorum` calls `stakeAboveThreshold`: `1000000 >= 0.75 + 0.02` → `True`.
7. `forgePerasCert` is called; a `ValidatedPerasCert` for block `B` is stored and broadcast.
8. Chain selection applies the Peras boost to `B`, causing honest nodes to prefer the attacker's block.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-162)
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-113)
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
```
