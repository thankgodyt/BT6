### Title
Peras Quorum Check Unit Mismatch: `PerasVoteStake` (absolute) vs `perasQuorumStakeThreshold` (relative) in `stakeAboveThreshold` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` in `SupportsPeras.hs` compares the accumulated `PerasVoteStake` (a `Rational` whose unit — absolute lovelace vs. relative fraction — is unspecified and unenforceable) directly against `perasQuorumStakeThreshold` (a hardcoded relative value of `3/4`). The code itself carries a developer-acknowledged TODO warning that the comparison is only correct when both operands are in the same units, but no normalization is performed or enforced. When the production stake-distribution plumbing is completed (replacing the current empty-map placeholder), an adversary who can inject a single vote whose `PerasVoteStake` is expressed as an absolute lovelace value will cause `stakeAboveThreshold` to return `True` unconditionally, forging a Peras certificate with a single vote and bypassing the quorum requirement entirely.

---

### Finding Description

**Root cause — `stakeAboveThreshold`** [1](#0-0) 

The function performs a bare `Rational` comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

`quorumThreshold` is `3/4` and `safetyMargin` is `2/100`, giving a combined threshold of `0.77` — a **relative** fraction of total stake. [2](#0-1) 

`PerasVoteStake` is a plain `Rational` newtype with no unit tag: [3](#0-2) 

The developer comment on `PerasVoteStake` explicitly states there is **no consensus** on whether the value should be absolute or relative, and the TODO on `stakeAboveThreshold` explicitly states the function is only correct when both operands share the same unit: [4](#0-3) 

**How `PerasVoteStake` is populated**

`validatePerasVote` assigns the stake value by a direct lookup from `PerasVoteStakeDistr` — whatever `Rational` is stored there is used verbatim, with no normalization: [5](#0-4) 

**Current production placeholder**

The production node-to-node handler currently passes `PerasVoteStakeDistr mempty` (an empty map), which causes all votes to fail validation at the `lookupPerasVoteStake` step. This is explicitly a temporary placeholder: [6](#0-5) 

The TODO comment confirms that real ledger stake data will be wired in. The `makePerasVotePoolWriterFromChainDB` function is already the production code path: [7](#0-6) 

**Quorum check call sites**

`stakeAboveThreshold` is called in `votesReachQuorum` (the smart constructor that gates certificate forging) and in `updateLoserVoteState`: [8](#0-7) [9](#0-8) 

---

### Impact Explanation

When the ledger stake distribution is plumbed in and `PerasVoteStakeDistr` is populated with absolute lovelace values (e.g., `1_000_000_000` for 1 ADA), the comparison becomes:

```
1_000_000_000  >=  0.77   →  True
```

This causes `stakeAboveThreshold` to return `True` for **any single vote** from any voter with positive stake, regardless of how small their actual share of total stake is. The consequence is that `votesReachQuorum` returns `Just` after a single vote, `forgePerasCert` is called, and a `ValidatedPerasCert` is produced and propagated — bypassing the intended ≥ 75% quorum requirement entirely.

Conversely, if the values are stored as absolute lovelace fractions of total supply (e.g., `1/45_000_000_000_000_000` for a tiny pool), the comparison is always `False`, permanently preventing any certificate from ever being forged regardless of actual stake participation.

Either direction constitutes a critical Peras voting/certificate bypass.

---

### Likelihood Explanation

The vulnerability is latent today because the production code uses `PerasVoteStakeDistr mempty`. However:

1. The empty-map placeholder is explicitly documented as temporary, with a TODO to wire in real ledger data.
2. The `makePerasVotePoolWriterFromChainDB` production path is already live and accepts votes from any peer over the Peras vote diffusion mini-protocol.
3. No normalization step exists anywhere between the ledger stake distribution and `stakeAboveThreshold`.
4. The developer comment on `PerasVoteStake` confirms there is no agreed-upon normalization convention.

Once the stake distribution plumbing is completed, the bug is immediately exploitable by any unprivileged peer that can send a single valid `PerasVote` message.

---

### Recommendation

1. **Enforce units at the type level**: Introduce distinct newtypes for absolute stake (`AbsolutePerasVoteStake`) and relative stake (`RelativePerasVoteStake`), and change `stakeAboveThreshold` to accept only the relative variant.
2. **Normalize at the boundary**: When populating `PerasVoteStakeDistr` from the ledger, divide each voter's absolute stake by the total stake of the committee, producing a relative value in `[0, 1]` before storing it.
3. **Alternatively**, change `stakeAboveThreshold` to accept the total stake as an additional parameter and perform the normalization internally, as the TODO comment suggests.

---

### Proof of Concept

With the empty-map placeholder replaced by a real distribution containing one voter with absolute stake `S` (any positive integer lovelace amount):

```haskell
let stakeDistr = PerasVoteStakeDistr $
      Map.singleton voterId (PerasVoteStake (fromIntegral S))
-- S = 1_000_000_000 (1 ADA)

-- validatePerasVote succeeds: stake = 1_000_000_000
-- stakeAboveThreshold mkPerasParams (PerasVoteStake 1_000_000_000)
--   = 1_000_000_000 >= (3/4 + 2/100)
--   = 1_000_000_000 >= 0.77
--   = True   ← quorum declared with one vote
```

`votesReachQuorum` returns `Just`, `forgePerasCert` is called, and a `ValidatedPerasCert` is produced and injected into the ChainDB after a single peer vote — with no actual quorum of stake. [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-148)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L600-606)
```haskell
updateLoserVoteState cfg vote oldState =
  assert (getPerasVoteTarget vote == ptvtTarget (ptvsVoteTally oldState)) $ do
    let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
        aboveQuorum = stakeAboveThreshold cfg (ptvtTotalStake newVoteTally)
     in if aboveQuorum
          then Left $ PerasTargetVoteLoser newVoteTally
          else Right $ PerasTargetVoteLoser newVoteTally
```
