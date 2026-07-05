### Title
Peras Quorum Check Unit Mismatch in `stakeAboveThreshold` Renders Certificate Quorum Bypassable When Stake Distribution Is Populated - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares accumulated `PerasVoteStake` (a `Rational` that may carry absolute ledger stake in lovelace) directly against `perasQuorumStakeThreshold` (a relative/normalized `Rational`, e.g. `3/4`), with no unit normalization. The code itself documents this as an unresolved assumption. When the production `PerasVoteStakeDistr` is populated with absolute lovelace values — the natural representation from the ledger — any single voter with positive stake satisfies `stake >= 0.77`, forging a certificate for an arbitrary block without a real quorum.

---

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake         = unPerasVoteStake voteStake          -- Rational, unit unknown
  quorumThreshold = unPerasQuorumStakeThreshold ...   -- Rational, always relative (e.g. 3/4)
  safetyMargin    = unPerasQuorumStakeThresholdSafetyMargin ...  -- e.g. 2/100
```

The code's own comment explicitly acknowledges the unit mismatch:

> "TODO: this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units. … Under the current implementation of 'PerasParams', this function only makes sense when both values are relative (normalized) values, so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

`PerasVoteStake` is a bare `Rational` newtype with no enforcement of normalization:

```haskell
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
```

`PerasVoteStakeDistr` is a `Map PerasVoterId PerasVoteStake` — also a bare map with no normalization contract. The values stored in it come directly from whatever the caller provides.

The production vote-ingest path in `makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB` calls `validatePerasVote mkPerasParams sd vote`, which looks up the voter's `PerasVoteStake` from the distribution and stores it verbatim in `ValidatedPerasVote.vpvVoteStake`. That value is then summed and passed to `stakeAboveThreshold` via `votesReachQuorum` → `updateCandidateVoteState`.

Currently, the production `NodeToNode.hs` wiring passes `pure (PerasVoteStakeDistr mempty)` — an empty distribution — so all votes fail `validatePerasVote` (voter not found) and the quorum check is never reached. However, the TODO comment in `NodeToNode.hs` explicitly states this is a placeholder:

> "TODO: when actual plumbing for Peras is ready, we will have to extract the committee selection data from the chainDB to pass it here, instead of relying on an empty the stake distribution."

When that plumbing is added and the distribution is populated from the ledger with absolute lovelace values (the natural representation), the comparison `absolute_lovelace >= 0.77` is trivially true for any voter with positive stake, completely bypassing the quorum requirement.

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute lovelace values (e.g., a voter holding 1 ADA has `PerasVoteStake = 1_000_000`), then:

- `stakeAboveThreshold` evaluates `1_000_000 >= 0.75 + 0.02 = 0.77` → `True`
- A **single vote** from any voter with positive stake causes `votesReachQuorum` to return `Just`, triggering `forgePerasCert`
- The forged certificate is accepted by `updateCandidateVoteState` and stored in the `PerasVoteDB`
- The certificate boosts an arbitrary block in chain selection, causing honest nodes to prefer a non-canonical chain

This is a **bypass of Peras certificate/quorum validation**: an unprivileged peer with any positive stake can forge a certificate for any block, manipulating chain selection for all nodes that accept the certificate.

---

### Likelihood Explanation

The bug is currently mitigated by the empty `PerasVoteStakeDistr mempty` placeholder in production. However:

1. The TODO comment in `NodeToNode.hs` explicitly states the placeholder will be replaced with real ledger data.
2. The ledger's natural stake representation is absolute lovelace — there is no automatic normalization step anywhere in the pipeline.
3. The comment in `SupportsPeras.hs` acknowledges "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake" — meaning the normalization step is not yet designed, let alone implemented.
4. Any developer wiring up the real stake distribution without reading the TODO comment in `stakeAboveThreshold` will produce the broken behavior.

---

### Recommendation

1. **Enforce normalization at the boundary**: `stakeAboveThreshold` should accept the total stake of the distribution and normalize internally, or `PerasVoteStakeDistr` should store pre-normalized relative values with a smart constructor that enforces `sum of all values == 1`.
2. **Add a type-level distinction** between absolute and relative stake (analogous to the `StakeRole`/`StakeType` phantom types already used in `Committee/WFA.hs`) to prevent mixing units at the type level.
3. **Remove the TODO and resolve the unit question** before wiring up the real stake distribution.

---

### Proof of Concept

**Scenario**: `PerasVoteStakeDistr` is populated with absolute lovelace values (1 ADA = 1,000,000 lovelace).

```
params = mkPerasParams
  -- perasQuorumStakeThreshold = 3/4
  -- perasQuorumStakeThresholdSafetyMargin = 2/100

stakeDistr = PerasVoteStakeDistr $ Map.fromList
  [ (attackerVoterId, PerasVoteStake (1_000_000 % 1))  -- 1 ADA absolute
  ]

-- validatePerasVote succeeds: attacker is in distribution
-- vpvVoteStake = PerasVoteStake (1_000_000 % 1)

-- stakeAboveThreshold check:
-- 1_000_000 >= (3/4) + (2/100) = 0.77  →  True

-- Result: votesReachQuorum returns Just, certificate is forged
-- for attacker's chosen block with a single vote
```

The attacker sends one `PerasVote` message via the Peras vote diffusion miniprotocol. `processVotes` validates it against the distribution, `updateCandidateVoteState` calls `votesReachQuorum`, `stakeAboveThreshold` returns `True`, and `forgePerasCert` produces a `ValidatedPerasCert` that boosts the attacker's chosen block in chain selection.

**Relevant code locations**:

- Root cause: [1](#0-0) 
- Quorum check call site: [2](#0-1) 
- Vote validation (stake lookup, no normalization): [3](#0-2) 
- Production wiring with empty placeholder: [4](#0-3) 
- Vote ingest pipeline: [5](#0-4) 
- Aggregation quorum trigger: [6](#0-5)

### Citations

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
