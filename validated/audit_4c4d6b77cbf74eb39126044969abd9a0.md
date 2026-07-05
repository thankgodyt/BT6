### Title
`PerasVoteStake` Unit Mismatch in Peras Quorum Threshold Comparison Enables Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value (a raw `Rational` that may be absolute ledger stake or relative/normalized stake) directly against `perasQuorumStakeThreshold` (a relative value, hardcoded to `3/4`) plus `perasQuorumStakeThresholdSafetyMargin` (`2/100`). There is no type-level or runtime enforcement that both operands are expressed in the same units. The code itself documents this as a known unresolved issue. When the actual ledger stake distribution is wired in (replacing the current empty-distribution placeholder), a caller that populates `PerasVoteStakeDistr` with absolute lovelace values would cause the comparison to always evaluate to `True` for any non-trivial stake, making every single vote immediately reach quorum and triggering unauthorized certificate forging. Conversely, if values are too small, quorum can never be reached. Either direction breaks the Peras voting invariant.

---

### Finding Description

In `SupportsPeras.hs`, `PerasVoteStake` is defined as a plain `Rational` newtype with no semantic tag distinguishing absolute from relative stake:

```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
```

The quorum check function `stakeAboveThreshold` then directly compares this value against the relative threshold:

```haskell
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

`perasQuorumStakeThreshold` is `3/4` and `perasQuorumStakeThresholdSafetyMargin` is `2/100`, both relative fractions. If `PerasVoteStake` values in `PerasVoteStakeDistr` are populated with absolute lovelace amounts (e.g., `1_000_000_000` for 1 ADA), then `stake >= 0.77` is trivially true for any voter, and a single vote from any peer immediately satisfies `votesReachQuorum`, causing `forgePerasCert` to be called and a `ValidatedPerasCert` to be accepted into the ChainDB.

The vote inbound path in `PerasVote.hs` calls `validatePerasVote mkPerasParams sd vote`, which assigns the stake from `PerasVoteStakeDistr` directly to `vpvVoteStake` without normalization. The `PerasVoteStakeDistr` is provided externally via `getStakeDistrSTM`, and the production wiring in `NodeToNode.hs` currently passes `pure (PerasVoteStakeDistr mempty)` as a placeholder — but the TODO comment there explicitly states this will be replaced with actual committee selection data. When that replacement occurs, the unit mismatch becomes exploitable.

The `validatePerasCert` degenerate stub (also in `SupportsPeras.hs`) compounds this: it accepts every inbound certificate unconditionally, meaning even the quorum gate is bypassed entirely for the cert diffusion path.

---

### Impact Explanation

**Bypass of Peras quorum/certificate checks.** If `PerasVoteStakeDistr` is populated with absolute stake values (the natural output of a ledger stake snapshot), a single vote from any unprivileged peer satisfies `stakeAboveThreshold`, causing `votesReachQuorum` to return `Just`, `forgePerasCert` to be called, and a `ValidatedPerasCert` to be stored in the ChainDB. This certificate then boosts a block's chain-selection weight by `perasWeight` (default 15), allowing an adversary to manipulate chain selection by forging certificates for arbitrary blocks without controlling the required quorum of stake. This is a bypass of Peras voting checks enabling unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The current production wiring in `NodeToNode.hs` passes `pure (PerasVoteStakeDistr mempty)`, which causes all votes to be rejected (no voter is in the empty distribution). This is an acknowledged temporary placeholder. The TODO comment explicitly states it will be replaced with actual committee selection data. Once that replacement is made — which is the intended production path — the unit mismatch becomes directly exploitable by any peer that can send a `PerasVote` message over the vote diffusion miniprotocol. No special privileges are required; the vote diffusion protocol is open to any connected peer.

---

### Recommendation

1. Introduce a phantom-typed or newtype-distinguished stake representation that separates absolute ledger stake from normalized/relative vote weight at the type level, preventing the two from being compared without an explicit normalization step.
2. `stakeAboveThreshold` should either accept a total-stake parameter and perform normalization internally, or require a pre-normalized `RelativePerasVoteStake` type that can only be constructed via an explicit normalization function.
3. The `validatePerasCert` stub must be replaced with actual cryptographic certificate validation before the Peras diffusion miniprotocol is enabled on any network where certificate boosts affect chain selection.

---

### Proof of Concept

**Root cause — unit mismatch in quorum check:** [1](#0-0) 

**Quorum threshold is a relative fraction (3/4), with no enforcement that `PerasVoteStake` is also relative:** [2](#0-1) 

**`votesReachQuorum` calls `stakeAboveThreshold` with the raw accumulated stake, then calls `forgePerasCert` if it returns `True`:** [3](#0-2) 

**`validatePerasVote` assigns stake from `PerasVoteStakeDistr` directly to `vpvVoteStake` without normalization:** [4](#0-3) 

**Production vote inbound path calls `validatePerasVote mkPerasParams sd vote` with the externally-provided stake distribution:** [5](#0-4) 

**Current production wiring uses empty distribution (placeholder); TODO acknowledges it will be replaced with real committee data:** [6](#0-5) 

**`validatePerasCert` degenerate stub accepts all certificates unconditionally:** [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-272)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-409)
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
            version
```
