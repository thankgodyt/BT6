### Title
Missing Cryptographic Signature Validation in Peras Vote Processing Allows Unauthorized Vote Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance defines a `PerasVote blk` data type with no signature field and a `validatePerasVote` implementation that performs no cryptographic verification. Peer-provided Peras votes are accepted as valid solely on the basis of the voter ID appearing in the stake distribution, with no proof of authenticity. An unprivileged peer can impersonate any registered stake pool voter, inject fabricated votes, accumulate quorum, and cause the node to forge and accept a certificate that boosts an attacker-chosen block in chain selection.

---

### Finding Description

The degenerate catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` in `Block/SupportsPeras.hs` defines the `PerasVote blk` data type without a signature field:

```haskell
data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
``` [1](#0-0) 

The corresponding `validatePerasVote` implementation ignores `_params` entirely and only checks whether the `pvVoteVoterId` appears in the stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [2](#0-1) 

This is explicitly acknowledged as incomplete with a TODO comment referencing issue #120: [3](#0-2) 

Similarly, `validatePerasCert` unconditionally returns `Right` for any certificate without performing any cryptographic or structural checks: [4](#0-3) 

The attacker-controlled entry path runs through `processVotes` in the Peras vote object diffusion layer, which calls `validatePerasVote` on every batch of votes received from a peer: [5](#0-4) 

Votes that pass `validatePerasVote` are stored in the `PerasVoteDB` and fed into `updatePerasRoundVoteStates`. When accumulated stake crosses the quorum threshold (checked by `stakeAboveThreshold`), a certificate is forged via `forgePerasCert` — which is also a stub that unconditionally returns `Right`: [6](#0-5) 

The resulting `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is consumed by `preferAnchoredCandidate` during chain selection, directly influencing which chain the node considers canonical. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer that knows the public stake pool IDs (which are on-chain public data) can craft `PerasVote` messages claiming to be any registered voter, for any round and any block target. Because `validatePerasVote` only checks stake distribution membership and performs no signature verification, these votes are accepted. By sending enough fabricated votes to exceed the quorum threshold, the attacker causes the local node to forge a `ValidatedPerasCert` boosting an attacker-chosen block. This certificate is then used in `preferAnchoredCandidate` to prefer the attacker's chain over the honest canonical chain, constituting a chain-selection manipulation that bypasses the Peras voting authorization entirely.

This matches the allowed impact: **Critical — bypass of Peras voting or certificate checks that enables unauthorized vote or certificate acceptance**, and **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The Peras vote mini-protocol is wired into the diffusion layer and `processVotes` is called on every inbound vote batch from any connected peer. No privileged access, key material, or stake is required — only knowledge of registered stake pool IDs, which are publicly available on-chain. The attack is deterministic and requires no brute force. Likelihood is **High** once the Peras vote diffusion protocol is active on any network (including private testnets).

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (analogous to `pvSignature` in the concrete `V1.PerasVote` type).
2. Implement `validatePerasVote` to verify the vote signature against the voter's registered verification key before accepting the vote.
3. Implement `validatePerasCert` to verify the aggregate BLS signature and all voter eligibility proofs before accepting a certificate.
4. Remove or gate the catch-all `instance StandardHash blk => BlockSupportsPeras blk` so that it cannot be used in any production code path without explicit opt-in.
5. Track resolution of issues #73 and #120 referenced in the TODO comments before enabling the Peras vote diffusion protocol on any network.

---

### Proof of Concept

1. Connect to a node with the Peras vote mini-protocol enabled.
2. Enumerate registered stake pool IDs from the on-chain stake distribution (public data).
3. Construct `PerasVote` messages with `pvVoteVoterId` set to each pool ID, `pvVoteRound` set to the current Peras round, and `pvVoteBlock` set to the attacker's chosen block point.
4. Send these votes via the Peras vote diffusion mini-protocol.
5. `processVotes` calls `validatePerasVote` on each vote; since each voter ID is in the stake distribution, all votes pass validation.
6. `updatePerasRoundVoteStates` accumulates the stake; once it exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`, `votesReachQuorum` returns `Just` and `forgePerasCert` is called.
7. The resulting `ValidatedPerasCert` with `vpcCertBoost = perasWeight params` is stored and used by `preferAnchoredCandidate` to boost the attacker's chosen block in chain selection. [8](#0-7) [9](#0-8)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-211)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L199-207)
```haskell
updatePerasRoundVoteState ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  PerasRoundVoteState blk ->
  Either (UpdateRoundVoteStateError blk) (PerasRoundVoteState blk)
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
```
