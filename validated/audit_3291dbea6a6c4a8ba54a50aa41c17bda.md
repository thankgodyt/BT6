### Title
Peras Certificate Validation Bypass Allows Unauthorized Chain Weight Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production default instance of `validatePerasCert` in `BlockSupportsPeras` unconditionally returns `Right` — performing zero cryptographic, quorum, or structural checks — and assigns the full `perasWeight` boost to any certificate presented by an unprivileged peer. This is the direct analog of the MonoX vulnerability: just as MonoX minted LP tokens based on a declared amount without verifying the actual token transfer, Ouroboros Consensus grants a full chain-weight boost based on a declared certificate without verifying any actual votes.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides the following production implementation of `validatePerasCert`:

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

This function is the sole gate between a raw `PerasCert blk` received from a peer and a `ValidatedPerasCert blk` that carries a `vpcCertBoost` used directly in chain selection. The function:

1. Performs **no signature verification** of the certificate.
2. Performs **no quorum check** — it does not verify that the certificate was backed by votes exceeding the `perasQuorumStakeThreshold`.
3. Performs **no voter eligibility check** — it does not verify that the voters were legitimate committee members.
4. Unconditionally assigns `vpcCertBoost = perasWeight params` (default: `PerasWeight 15`).

The `ValidatedPerasCert` produced by this stub is then stored in `PerasCertDB` and consumed by chain selection via `weightBoostOfFragment` and `wsvTotalWeight`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

Chain selection in `preferCandidate` compares `wsvTotalWeight` values, so a fake boost of 15 directly overrides the honest chain's length advantage.

The `validatePerasVote` stub has the same TODO marker and also skips cryptographic signature verification of individual votes, only checking stake-distribution membership.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker who can send a `PerasCert` referencing any block already present in the node's `VolatileDB` (i.e., any recently received block on any fork) can inject a fake certificate that grants that block a `PerasWeight 15` boost. Because `wsvTotalWeight = BlockNo + WeightBoost`, a fork at block height `N` with a fake cert becomes preferred over the honest chain at height `N + 14`. The node will execute `chainSelectionForBlock` for the boosted block, potentially rolling back up to 14 honest blocks and switching to the adversarial fork. This violates the chain-selection security assumption of Peras.

---

### Likelihood Explanation

**High.** The entry path requires no privileged keys, no stake, and no cryptographic material. Any peer connected to the node via the Peras object-diffusion miniprotocol can send a `PerasCert` with an arbitrary `pcCertBoostedBlock`. The `validatePerasCert` stub will accept it unconditionally. The `chainSelSync` handler in `ChainSel.hs` will then trigger chain selection for the boosted block. The only guard is that the boosted block must already be in the `VolatileDB`, which is trivially satisfied for any block the attacker has previously diffused to the target node.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real implementation that:
1. Verifies the aggregate KES/BLS signature over the certificate's voter set.
2. Verifies that each listed voter was a legitimate committee member for the claimed round (checking against the epoch's `VotingCommittee`).
3. Verifies that the total stake of the listed voters exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. Verifies VRF outputs for non-persistent voters.

Until this is done, the `addPerasCertAsync` entry point should be gated so that it is unreachable from untrusted peers, or the Peras cert diffusion miniprotocol should be disabled in production builds.

---

### Proof of Concept

**Root cause — stub always returns `Right`:** [1](#0-0) 

**The `vpcCertBoost` is used directly in chain-weight comparison:** [2](#0-1) 

**Chain selection triggers on the boosted block after cert insertion:** [3](#0-2) 

**The `ValidatedPerasCert` type carries the boost that drives selection:** [4](#0-3) 

**Attack sequence:**

1. Attacker connects to a target node via the Peras cert diffusion miniprotocol.
2. Attacker observes a block `B` at height `N` on a competing fork already in the node's `VolatileDB`.
3. Attacker crafts a `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(B) }` with no valid votes.
4. Attacker sends the cert; the node calls `validatePerasCert` which returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }` without any check.
5. `chainSelSync` triggers `chainSelectionForBlock` for `B`.
6. `wsvTotalWeight` for the fork containing `B` becomes `N + 15`, beating the honest chain at any height up to `N + 14`.
7. The node rolls back up to 14 honest blocks and adopts the adversarial fork. [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
