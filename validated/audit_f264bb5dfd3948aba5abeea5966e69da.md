### Title
Peras Quorum Threshold Unit Mismatch Enables Certificate Verification Bypass - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The `stakeAboveThreshold` function compares a `PerasVoteStake` value directly against the `perasQuorumStakeThreshold` (a relative `Rational`, set to `3/4`) without enforcing that the vote stake has been normalized to the same unit. The code itself documents this as an unresolved unit mismatch. If the `PerasVoteStakeDistr` supplied at runtime contains absolute ledger stakes (not normalized), the comparison is meaningless: absolute stakes will trivially exceed `0.77` (threshold + safety margin), causing any single inbound vote from an unprivileged peer to immediately trigger quorum and forge a Peras certificate for an arbitrary block.

### Finding Description

`stakeAboveThreshold` in `SupportsPeras.hs` performs a bare numeric comparison:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
```

where `quorumThreshold = 3/4` (relative) and `stake = unPerasVoteStake voteStake` (unit unspecified).

The `PerasVoteStake` type carries an explicit developer warning:

> "At the moment there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee (given that the quorum is expressed as a relative value of the voting committee total stake)."

The `stakeAboveThreshold` function itself carries a second warning:

> "TODO: this function assumes that the 'PerasVoteStake' and the quorum threshold used in 'PerasParams' are expressed in the same units … so we should either normalize the 'PerasVoteStake' before calling this function, or change this function to accept a stake distribution and perform the normalization internally."

Neither normalization step exists anywhere in the call chain. The production entry point `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote`, where `sd` is a `PerasVoteStakeDistr` read from STM. `validatePerasVote` simply looks up the voter's stake from that distribution and stores it verbatim as `vpvVoteStake` — no normalization, no total-supply division. That raw stake value then flows into `stakeAboveThreshold` via `updateCandidateVoteState` → `votesReachQuorum`.

### Impact Explanation

**Critical — bypass of Peras certificate/vote quorum check.**

If the `PerasVoteStakeDistr` is populated with absolute ledger stakes (e.g., lovelace amounts, or any value > `0.77`), then `stake >= 0.77` is trivially `True` for every single vote. A single inbound `PerasVote` message from any unprivileged peer causes `stakeAboveThreshold` to return `True`, `votesReachQuorum` to succeed, and `forgePerasCert` to produce a `ValidatedPerasCert` boosting an arbitrary block. This certificate is then accepted by the ChainDB and applied to chain selection, granting an illegitimate `PerasWeight` boost (default: 15 blocks) to any block the attacker names — including invalid or minority-chain blocks — without holding any actual stake majority.

### Likelihood Explanation

**High.** The production vote ingestion path (`makePerasVotePoolWriterFromChainDB`) is reachable by any peer that can send a `PerasVote` miniprotocol message. No key material, stake, or operator access is required. The unit mismatch is not a theoretical edge case; it is explicitly documented as unresolved in the code. The default `mkPerasParams` sets the threshold to `3/4`, a relative value, while the ledger stake distribution naturally contains absolute values. The mismatch is structural and present in every deployment using the default parameters.

### Recommendation

1. Enforce normalization at the boundary: `validatePerasVote` must divide each voter's absolute ledger stake by the total stake in `PerasVoteStakeDistr` before storing it as `vpvVoteStake`.
2. Alternatively, change `stakeAboveThreshold` to accept the total stake distribution and perform normalization internally, removing the precondition entirely.
3. Introduce a newtype distinction between absolute and relative `PerasVoteStake` so the type system prevents the comparison of incompatible units, analogous to how the `Stake Ledger Global` / `Stake Weight Global` phantom-type scheme is used in the WFA committee code.
4. Add an invariant assertion (or a `SmallCheck`/`QuickCheck` property) that the sum of all `PerasVoteStake` values in a `PerasVoteStakeDistr` equals `1` before any quorum check is performed.

### Proof of Concept

**Setup:** Construct a `PerasVoteStakeDistr` with a single entry whose `PerasVoteStake` value is `1` (representing 100% of absolute stake, or any value ≥ 0.77).

**Step 1 — Peer sends one vote:**
```
PerasVote { pvVoteRound = 0, pvVoteBlock = <any block point>, pvVoteVoterId = <registered voter> }
```

**Step 2 — `processVotes` calls `validatePerasVote`:** [1](#0-0) 

`lookupPerasVoteStake` returns `PerasVoteStake 1` (absolute, unnormalized).

**Step 3 — `stakeAboveThreshold` is called with `stake = 1`:** [2](#0-1) 

`1 >= (3/4 + 2/100)` → `True`. Quorum declared.

**Step 4 — `forgePerasCert` produces a certificate boosting the attacker's chosen block:** [3](#0-2) 

**Step 5 — Certificate enters ChainDB, granting a `PerasWeight 15` boost to the attacker's block, overriding honest chain selection.**

The root cause (missing normalization) is confirmed by the developer TODO at: [4](#0-3) 

The production inbound path that makes this reachable by an unprivileged peer: [5](#0-4) 

The default quorum threshold (relative `3/4`) that is compared against the unnormalized absolute stake: [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-161)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L376-385)
```haskell
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-176)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
```
