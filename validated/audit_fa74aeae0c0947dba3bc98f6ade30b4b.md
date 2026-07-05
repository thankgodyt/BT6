### Title
Peras Quorum Check Compares Absolute Vote Stake Against Relative Threshold Without Normalization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

`stakeAboveThreshold` directly compares a `PerasVoteStake` value (which can hold absolute ledger stake) against `PerasQuorumStakeThreshold` (a relative/normalized `Rational`, e.g. `0.75`) with no unit conversion. The code itself documents this as an unresolved mismatch. When the `PerasVoteStakeDistr` is populated with absolute ledger-stake values — the natural result of reading from the ledger — any voter whose raw stake exceeds the threshold literal (e.g. `> 0.75 lovelace`) satisfies quorum alone, allowing a single crafted vote from an unprivileged peer to forge a Peras certificate.

---

### Finding Description

`PerasVoteStake` is a bare `Rational` newtype with no enforced unit:

```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
newtype PerasVoteStake = PerasVoteStake { unPerasVoteStake :: Rational }
``` [1](#0-0) 

`stakeAboveThreshold` then compares this raw value directly against the relative quorum threshold, with the code itself flagging the assumption as unverified:

```haskell
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. ...
-- this function only makes sense when both values are relative (normalized)
-- values, so we should either normalize the 'PerasVoteStake' before calling
-- this function, or change this function to accept a stake distribution and
-- perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [2](#0-1) 

`validatePerasVote` assigns the stake directly from the `PerasVoteStakeDistr` lookup with no normalization:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
``` [3](#0-2) 

`votesReachQuorum` accumulates these raw stakes and passes the sum directly to `stakeAboveThreshold`:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)
votesHaveEnoughStake = stakeAboveThreshold cfg totalVoteStake
``` [4](#0-3) 

The production diffusion handler in `NodeToNode.hs` wires this path directly to the network, passing whatever `PerasVoteStakeDistr` is provided (currently a placeholder `mempty`, with a TODO to replace it with real ledger data):

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
(pure (PerasVoteStakeDistr mempty))
``` [5](#0-4) 

The `makePerasVotePoolWriterFromChainDB` function calls `validatePerasVote mkPerasParams sd vote` using whatever distribution is supplied, with no normalization step before or after: [6](#0-5) 

---

### Impact Explanation

When the `PerasVoteStakeDistr` is populated with absolute ledger-stake values (e.g., lovelace counts in the billions), and `perasQuorumStakeThreshold` is a relative value such as `3 % 4` (75%), the comparison `stake >= 0.75` is trivially satisfied by any voter with more than `0.75` lovelace of absolute stake — i.e., every real stake pool. A single vote from one unprivileged peer causes `stakeAboveThreshold` to return `True`, `votesReachQuorum` to succeed, and `forgePerasCert` to produce a `ValidatedPerasCert`. That certificate is then stored in the ChainDB and used to boost the target block's chain-selection weight by `perasWeight`. An adversary can therefore cause honest nodes to prefer an adversarially chosen block over the canonical chain, constituting a chain-selection safety failure driven by a fraudulent Peras certificate.

This maps to the allowed impact: **"Bypass of... Peras voting or certificate checks... that enables unauthorized... certificate acceptance"** and **"chain selection... bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."**

---

### Likelihood Explanation

The mismatch is self-documented in the production source as an open TODO with no enforcement mechanism. The `PerasVoteStake` type carries no phantom unit tag, so any caller that populates `PerasVoteStakeDistr` from raw ledger data (the only realistic source) will produce absolute values. The quorum threshold in `mkPerasParams` is a relative `Rational`. The two sides of the comparison will be in different units as soon as real ledger plumbing replaces the current `mempty` placeholder, which is the explicitly stated next step in the TODO comment. No special privileges, key compromise, or majority stake are required — only the ability to send a `PerasVote` message over the node-to-node diffusion protocol.

---

### Recommendation

1. **Enforce normalization at the boundary.** `validatePerasVote` should normalize the looked-up absolute stake against the total stake in the distribution before storing it in `vpvVoteStake`. This mirrors the fix suggested in the external report: convert at the point of assignment so that the stored value and the threshold are always in the same unit.

2. **Introduce a phantom-typed wrapper.** Replace the bare `Rational` in `PerasVoteStake` with a phantom-typed newtype (e.g., `PerasVoteStake 'Normalized` vs `PerasVoteStake 'Absolute`) so the type system prevents `stakeAboveThreshold` from accepting an un-normalized value.

3. **Pass total stake into `stakeAboveThreshold`.** Alternatively, change the signature to accept the total committee stake and perform the division internally, eliminating the caller's responsibility to pre-normalize.

---

### Proof of Concept

**Setup (private testnet):**

1. Configure a node with `mkPerasParams` defaults: `perasQuorumStakeThreshold = 3 % 4`.
2. Populate `PerasVoteStakeDistr` with one entry: `voterId -> PerasVoteStake (1_000_000_000_000 % 1)` (1 trillion lovelace, a realistic pool stake).
3. Send a single `PerasVote` for an adversarially chosen block from that voter via the Peras vote diffusion mini-protocol.

**Execution trace:**

- `validatePerasVote` looks up the voter → `vpvVoteStake = 1_000_000_000_000 % 1`.
- `votesReachQuorum` computes `totalVoteStake = 1_000_000_000_000 % 1`.
- `stakeAboveThreshold`: `1_000_000_000_000 >= 3/4 + 0` → `True`.
- `forgePerasCert` produces a `ValidatedPerasCert` boosting the adversary's block.
- ChainDB stores the certificate; chain selection adds `perasWeight` to the adversary's block, causing honest nodes to prefer it over the canonical tip.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L267-270)
```haskell
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
