### Title
`stakeAboveThreshold` Compares Unnormalized `PerasVoteStake` Against Relative Quorum Threshold — Unit Mismatch Enables Trivial Peras Certificate Forgery - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares a `PerasVoteStake` value against `perasQuorumStakeThreshold` (a relative `Rational` like `3/4`) without enforcing that both operands are in the same unit. The code itself documents this invariant is unresolved. When the stake distribution is wired up with absolute ledger stake values (lovelace), any single vote from any registered voter trivially satisfies the quorum check, allowing unauthorized Peras certificate forgery and chain-selection manipulation.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake          -- Rational, unit unknown
  quorumThreshold = unPerasQuorumStakeThreshold ...   -- Rational, e.g. 3/4
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ...  -- e.g. 2/100
```

The code's own NOTE comment acknowledges the problem:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."

And the TODO on `stakeAboveThreshold` itself states:

> "this function assumes that the `PerasVoteStake` and the quorum threshold used in `PerasParams` are expressed in the same units … we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

`PerasVoteStake` is populated from `PerasVoteStakeDistr` via `lookupPerasVoteStake` inside `validatePerasVote`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

`PerasVoteStakeDistr` is a plain `Map PerasVoterId PerasVoteStake` with no enforced normalization. If it is populated with absolute ledger stake (e.g., lovelace amounts like `1_000_000_000_000`), then `stake >= 3/4 + 2/100` is trivially `True` for every voter, and quorum is reached with a single vote.

The aggregation path that uses this check is `votesReachQuorum` → `stakeAboveThreshold`, called from `updatePerasRoundVoteStates` in `Peras/Vote/Aggregation.hs`, which forges a `ValidatedPerasCert` when quorum is reached. That certificate is then stored in `PerasCertDB` and used to compute `wsvWeightBoost` in chain selection via `weightBoostOfFragment`.

---

### Impact Explanation

**Critical — Bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

If `PerasVoteStake` is absolute (lovelace) while `perasQuorumStakeThreshold` is relative (`3/4`):
- Any single vote from any registered voter satisfies `stake >= 3/4`
- A Peras certificate is forged for the adversary's chosen block
- The certificate adds `perasWeight` (e.g., `PerasWeight 15`) to that block's `wsvTotalWeight`
- Honest nodes prefer the boosted chain over the canonical chain, causing chain-selection divergence

Conversely, if `PerasVoteStake` is relative but `perasQuorumStakeThreshold` is accidentally treated as absolute, quorum is never reached, silently disabling Peras and its finality guarantees.

---

### Likelihood Explanation

The current production wiring in `NodeToNode.hs` passes `pure (PerasVoteStakeDistr mempty)` — an empty distribution — so the bug is not yet exploitable on mainnet. However:

1. The empty distribution is explicitly a placeholder pending the TODO resolution.
2. When the stake distribution is wired up from the ledger, the normalization decision is unresolved by design.
3. If the implementer uses raw `IndividualPoolStake` (absolute lovelace) from the ledger without normalizing to `[0,1]`, the mismatch activates immediately.
4. An adversary who can send a single valid vote (i.e., any registered stake pool operator) over the vote diffusion miniprotocol would trigger the trivial quorum path.

---

### Recommendation

`stakeAboveThreshold` must enforce that both operands are in the same unit before comparison. The fix should either:

1. **Normalize at assignment time**: when constructing `PerasVoteStakeDistr`, divide each pool's absolute stake by the total active stake so all `PerasVoteStake` values are in `[0,1]`.
2. **Normalize at comparison time**: pass the total stake into `stakeAboveThreshold` and divide `unPerasVoteStake voteStake` by it before comparing against `perasQuorumStakeThreshold`.
3. **Use distinct types**: introduce `AbsolutePerasVoteStake` and `RelativePerasVoteStake` newtypes so the type system prevents mixing them.

The `PerasQuorumStakeThreshold` type should also carry a unit annotation or be renamed to `PerasRelativeQuorumStakeThreshold` to make the invariant explicit.

---

### Proof of Concept

**Entry path**: unprivileged peer → vote diffusion miniprotocol → `processVotes` → `validatePerasVote` → `PerasVoteDB.addVote` → `updatePerasRoundVoteStates` → `votesReachQuorum` → `stakeAboveThreshold`.

**Concrete scenario** (once stake distribution is wired up with absolute values):

1. Adversary is a registered stake pool with absolute stake `s = 1_000_000_000_000` lovelace.
2. `PerasVoteStakeDistr` maps adversary's `PerasVoterId` → `PerasVoteStake (1_000_000_000_000 % 1)`.
3. Adversary sends one `PerasVote` for block `B_adv` via the vote diffusion protocol.
4. `validatePerasVote` assigns `vpvVoteStake = PerasVoteStake (1_000_000_000_000 % 1)`.
5. `stakeAboveThreshold` evaluates `1_000_000_000_000 >= 3/4 + 2/100` → `True`.
6. `forgePerasCert` produces a `ValidatedPerasCert` for `B_adv` with `vpcCertBoost = PerasWeight 15`.
7. `PerasCertDB` stores the certificate; `getWeightSnapshot` returns a `PerasWeightSnapshot` boosting `B_adv` by 15.
8. `weightedSelectView` computes `wsvTotalWeight` for any chain containing `B_adv` as 15 higher than competing chains.
9. Honest nodes switch to the adversary's chain.

**Key code references**: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L93-109)
```haskell
-- | Total stake needed to forge a Peras certificate.
newtype PerasQuorumStakeThreshold
  = PerasQuorumStakeThreshold {unPerasQuorumStakeThreshold :: Rational}
  deriving Show via Quiet PerasQuorumStakeThreshold
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)

-- | Safety margin needed on top of the quorum stake threshold.
--
-- NOTE: this is needed to account for an extremely unlikely local sortition
-- where not enough honest non-persistent parties decide to vote in a round.
-- This mostly depend on the expected size of the voting committee.
newtype PerasQuorumStakeThresholdSafetyMargin
  = PerasQuorumStakeThresholdSafetyMargin {unPerasQuorumStakeThresholdSafetyMargin :: Rational}
  deriving Show via Quiet PerasQuorumStakeThresholdSafetyMargin
  deriving stock Generic
  deriving newtype (Eq, Ord, NoThunks, Condense)
```
