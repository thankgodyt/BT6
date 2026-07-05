### Title
Peras Quorum Check Uses Unnormalized `PerasVoteStake` Against a Relative Threshold — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value directly against the relative `perasQuorumStakeThreshold` (3/4) without first normalizing the vote stake. The function's own TODO comment explicitly acknowledges that the comparison is only correct when both operands are expressed in the same units (both relative), but no normalization is enforced. If the `PerasVoteStakeDistr` supplied to `validatePerasVote` is populated with absolute ledger-stake values rather than normalized fractions, any single vote whose absolute stake exceeds 0.77 would satisfy the quorum predicate, allowing an unprivileged peer to trigger certificate forging with far less than the required 3/4 of committee stake.

---

### Finding Description

`stakeAboveThreshold` is the sole gate that decides whether a set of Peras votes reaches quorum:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake     = unPerasVoteStake voteStake          -- Rational from PerasVoteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold (perasQuorumStakeThreshold params)   -- 3/4
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin (perasQuorumStakeThresholdSafetyMargin params) -- 2/100
``` [1](#0-0) 

The comment immediately above the function states the problem explicitly:

> "this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

The `PerasVoteStake` fed into this function originates from `PerasVoteStakeDistr`, which is looked up verbatim in `validatePerasVote` without any normalization step:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [3](#0-2) 

`votesReachQuorum` then sums the raw `vpvVoteStake` values and passes the total directly to `stakeAboveThreshold`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) 

The same unnormalized path is exercised in `updateCandidateVoteState` (the live certificate-forging path): [5](#0-4) 

The `PerasParams` default sets `perasQuorumStakeThreshold = 3/4` and `perasQuorumStakeThresholdSafetyMargin = 2/100`, giving an effective threshold of `0.77`: [6](#0-5) 

---

### Impact Explanation

If `PerasVoteStakeDistr` is populated with absolute ledger-stake values (e.g., lovelace counts or any `Rational > 0.77`), then a **single vote** from any voter whose absolute stake exceeds 0.77 satisfies `stake >= 0.77`, causing `votesReachQuorum` to return `Just` and triggering `forgePerasCert`. The forged certificate is then accepted by `addPerasCertAsync` into the ChainDB and used to boost the target block's chain-selection weight. An adversary who can submit a single crafted Peras vote to a node running such a distribution can cause the node to accept an unauthorized Peras certificate, boosting an arbitrary block by `perasWeight` (default 15) and potentially causing it to be preferred over the honest chain. This is a bypass of the Peras voting/certificate quorum check enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The `PerasVoteStakeDistr` is constructed externally and passed into `validatePerasVote`. The code imposes no type-level or runtime constraint that the values must be normalized. The TODO comment confirms the normalization contract is not enforced. Any implementation path that derives the distribution from absolute ledger pool-stake values (e.g., lovelace) rather than normalized fractions silently triggers the wrong comparison. Because the Peras committee-selection code (`WFA.hs`) works with `LedgerStake` (absolute) internally and the conversion to `PerasVoteStake` is not shown to perform normalization, the risk of an accidental absolute-value population is concrete, not merely hypothetical.

---

### Recommendation

1. **Enforce normalization at the boundary**: `stakeAboveThreshold` (or its callers) should normalize `PerasVoteStake` by dividing by the total stake of the distribution before comparing against the relative threshold, or the function signature should be changed to accept the total stake and perform normalization internally.
2. **Add a type-level or runtime invariant**: Introduce a `NormalizedPerasVoteStake` newtype (values in `[0,1]`) and require callers to produce it via a smart constructor that performs the division, preventing the wrong unit from reaching the comparison.
3. **Resolve the TODO**: The comment at line 153–161 of `SupportsPeras.hs` explicitly flags this as unresolved; it should be treated as a security-critical fix, not a deferred cleanup.

---

### Proof of Concept

**Setup**: Populate `PerasVoteStakeDistr` with a single entry mapping voter `V` to `PerasVoteStake 1` (absolute stake of 1 lovelace, or any value ≥ 0.77).

**Step 1**: Peer sends one `PerasVote` from voter `V`.

**Step 2**: Node calls `validatePerasVote _params distr vote`. Since `V` is in the distribution, it returns `Right (ValidatedPerasVote { vpvVoteStake = PerasVoteStake 1 })`.

**Step 3**: `updateCandidateVoteState` calls `votesReachQuorum cfg [validatedVote]`.

**Step 4**: `totalVoteStake = PerasVoteStake 1`. `stakeAboveThreshold params (PerasVoteStake 1)` evaluates `1 >= 3/4 + 2/100 = 77/100` → **True**.

**Step 5**: `votesReachQuorum` returns `Just votesWithQuorum`. `forgePerasCert` is called and returns a `ValidatedPerasCert` boosting the adversary's chosen block by weight 15.

**Step 6**: The certificate is added to the ChainDB via `addPerasCertAsync`, and the boosted block gains a chain-selection advantage of 15 weight units over the honest chain, potentially causing the node to switch to the adversary's fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
