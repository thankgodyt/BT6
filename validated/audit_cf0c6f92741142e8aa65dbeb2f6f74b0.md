### Title
Peras Quorum Threshold Bypass via Unnormalized `PerasVoteStake` in `stakeAboveThreshold` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` compares a `PerasVoteStake` value directly against the relative quorum threshold (`3/4 + 2/100 = 0.77`) without any normalization step. The code itself carries a `TODO` acknowledging that the two sides of the comparison must be in the same units, but no normalization is enforced. The production node-to-node handler currently neutralizes this by passing an empty `PerasVoteStakeDistr` (causing all votes to be rejected), but the same handler carries a `TODO` stating it will be replaced with real committee selection data. When that plumbing lands, if the distribution is populated with absolute ledger-stake values (the natural representation), any single vote from any voter whose absolute stake exceeds `0.77` lovelace — effectively every voter — will satisfy the threshold, allowing a single peer-submitted vote to forge a Peras certificate and boost an arbitrary block's chain-selection weight.

---

### Finding Description

**Root cause — unit mismatch in `stakeAboveThreshold`**

`stakeAboveThreshold` in `Block/SupportsPeras.hs` performs a bare numeric comparison:

```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `quorumThreshold = 3/4` and `safetyMargin = 2/100` (both relative fractions of total stake). The function's own documentation states:

> TODO: this function assumes that the `PerasVoteStake` and the quorum threshold … are expressed in the same units … this function only makes sense when both values are relative (normalized) values, so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally.

No normalization is performed anywhere in the call chain. `validatePerasVote` (the only production instance) simply copies the raw value out of `PerasVoteStakeDistr`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

**Current production state — empty distribution**

The node-to-node handler in `NodeToNode.hs` currently passes `(pure (PerasVoteStakeDistr mempty))`, which causes every vote to fail `lookupPerasVoteStake` and be rejected. The same site carries:

> TODO: when actual plumbing for Peras is ready, we will have to extract the committee selection data from the chainDB to pass it here, instead of relying on an empty the stake distribution.

**Trigger condition**

When the empty placeholder is replaced with real committee data, the `PerasVoteStakeDistr` will be populated from the ledger stake distribution. Ledger stake is measured in lovelace (absolute integers, e.g. `10^12`). Comparing `10^12 >= 0.77` is always `True`. A single vote from any voter present in the distribution will therefore satisfy `votesHaveEnoughStake` inside `votesReachQuorum`, causing `updateCandidateVoteState` to call `forgePerasCert` and produce a `ValidatedPerasCert` with the configured `perasWeight` boost.

**Compounding factor — no signature in the degenerate `PerasVote` instance**

The degenerate `BlockSupportsPeras` instance (the only one in the codebase) defines `PerasVote` without a cryptographic signature field, and `validatePerasVote` performs no signature check. Any peer can therefore craft a vote for any voter ID that appears in the distribution without possessing that voter's key.

---

### Impact Explanation

A crafted `PerasVote` message delivered over the vote-diffusion mini-protocol causes the receiving node to forge a `ValidatedPerasCert` for an attacker-chosen block. That certificate is stored in the `PerasCertDB` / `ChainDB` and applied as a `PerasWeight` boost (default: 15 blocks) to the targeted block's chain-selection weight via `weightBoostOfFragment`. This lets an unprivileged peer make an honest node prefer a non-canonical or adversarially chosen chain, constituting a **bypass of Peras certificate/vote verification** and a **chain-selection manipulation** beyond the intended security assumptions.

Impact class: **Critical** — bypass of certificate/vote verification enabling unauthorized certificate acceptance; **High** — chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

The vulnerability is latent today (empty distribution blocks it) but is explicitly scheduled to be activated: the `TODO` in `NodeToNode.hs` is the only barrier. Once real committee data is wired in — a planned, tracked change — the bug becomes immediately exploitable by any peer that can connect to the vote-diffusion port. No stake, no keys, no prior knowledge beyond a valid voter ID from the public ledger state is required.

Likelihood: **High** once the plumbing TODO is resolved; **Medium** in the current codebase state given the explicit roadmap item.

---

### Recommendation

1. **Enforce normalization at the boundary.** `stakeAboveThreshold` should divide the accumulated `PerasVoteStake` by the total stake of the distribution before comparing against the relative threshold, or accept the total stake as an additional parameter.
2. **Type-level separation.** Introduce distinct newtypes for absolute ledger stake and normalized vote stake so the compiler prevents mixing them.
3. **Resolve the TODO before activating real committee data.** The normalization fix must land before `PerasVoteStakeDistr mempty` is replaced with live data.
4. **Add signature verification.** The `PerasVote` type and `validatePerasVote` must include and verify a cryptographic signature before the vote-diffusion protocol is enabled in production.

---

### Proof of Concept

```
Setup:
  - Node running with Peras enabled.
  - PerasVoteStakeDistr populated with absolute ledger stakes, e.g.:
      { voter_A -> PerasVoteStake (1_000_000_000_000 % 1) }

Attack:
  1. Attacker connects via the PerasVoteDiffusion mini-protocol.
  2. Attacker sends:
       PerasVote { pvVoteRound = r, pvVoteBlock = adversarialBlock, pvVoteVoterId = voter_A }
  3. processVotes calls validatePerasVote:
       lookupPerasVoteStake returns Just (PerasVoteStake (1_000_000_000_000 % 1))
       => ValidatedPerasVote { vpvVoteStake = 1_000_000_000_000 % 1 }
  4. updateCandidateVoteState calls votesReachQuorum:
       totalVoteStake = 1_000_000_000_000 % 1
       stakeAboveThreshold: 1_000_000_000_000 >= 3/4 + 2/100  =>  True
       => certificate forged for adversarialBlock
  5. Certificate stored; adversarialBlock receives +15 weight boost in chain selection.
  6. Honest node switches to attacker's chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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
