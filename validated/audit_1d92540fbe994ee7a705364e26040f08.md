### Title
Unconditional Certificate Acceptance in Default `BlockSupportsPeras` Instance Enables Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default catch-all `BlockSupportsPeras` instance, which covers all block types via `instance StandardHash blk => BlockSupportsPeras blk`, implements `validatePerasCert` as an unconditional stub that always returns `Right` — accepting every certificate without performing any cryptographic, quorum, or structural validation. An unprivileged peer can send crafted `PerasCert` objects over the ObjectDiffusion mini-protocol; each accepted certificate injects a `PerasWeight` boost into the `PerasWeightSnapshot` used by chain selection, allowing the attacker to make an honest node prefer an adversarial chain over the canonical one.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the security gate for accepting incoming Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only deployed instance — the catch-all `instance StandardHash blk => BlockSupportsPeras blk` — implements this function as:

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
``` [1](#0-0) 

No cryptographic verification, no quorum check, no structural check — every certificate is accepted and assigned the full `perasWeight` boost (currently `PerasWeight 15` from `mkPerasParams`). [2](#0-1) 

The same pattern applies to `validatePerasVote`, which accepts any vote from a registered voter without verifying the vote signature:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

The accepted `ValidatedPerasCert` is stored in `PerasCertDB` and its boosted block point is inserted into the `PerasWeightSnapshot`. Chain selection then uses `totalWeightOfFragment`, which sums block count and weight boost, to compare candidate chains:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
    ...
``` [4](#0-3) 

`wsvTotalWeight` is `BlockNo + weightBoostOfFragment`, so each fake certificate adds 15 weight units to an arbitrary block on an adversarial chain. [5](#0-4) 

The `stakeAboveThreshold` quorum check exists but is never reached during certificate acceptance because `validatePerasCert` returns `Right` before any quorum logic runs. [6](#0-5) 

This is structurally identical to the Pool contract bug: a component designed to enforce authorization (certificate validity / upgrade authorization) has its initialization/implementation omitted, leaving the check permanently bypassed.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker controlling one peer connection can:
1. Craft `PerasCert` objects referencing arbitrary blocks on an adversarial fork.
2. Deliver them via the ObjectDiffusion mini-protocol.
3. Each accepted certificate adds `PerasWeight 15` to the adversarial chain's total weight.
4. With enough fake certificates, `wsvTotalWeight(adversarial) > wsvTotalWeight(honest)`, causing the node to switch to the adversarial chain.

Because `perasWeight = 15` and a block contributes weight 1, a single fake certificate outweighs 15 honest blocks. An attacker with a short adversarial fork can overcome the honest chain's length advantage with a small number of crafted certificates.

---

### Likelihood Explanation

**Medium-High.** The ObjectDiffusion mini-protocol for Peras certificates is a public-facing network interface reachable by any peer. No keys, stake, or privileged access are required to craft a `PerasCert` — the data type is a plain record with no cryptographic binding at construction time. The only prerequisite is that Peras is enabled in the era configuration (`eraPerasRoundLength = PerasEnabled ...`). On a private testnet or future mainnet deployment with Peras active, this is immediately exploitable by any connecting peer.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with full validation before Peras is enabled in any network. At minimum, the implementation must:

1. **Verify the aggregate BLS signature** over `(roundNo, boostedBlock)` against the claimed voter set.
2. **Verify each voter's eligibility** (membership in the voting committee for the given round, VRF proof for non-persistent voters).
3. **Check quorum**: the total stake of the voters must satisfy `stakeAboveThreshold params totalStake`.
4. **Reject certificates** referencing unknown or future rounds.

Until a real implementation exists, the node should refuse to enable Peras (`eraPerasRoundLength = NoPerasEnabled`) in any network configuration, enforced by a runtime guard in the certificate acceptance path rather than relying solely on era configuration.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect a malicious peer to an honest node.
2. Craft a `PerasCert blk` with `pcCertRound = r` and `pcCertBoostedBlock = pt` where `pt` is a block on an adversarial fork.
3. Deliver it via the ObjectDiffusion mini-protocol.
4. Observe that `validatePerasCert mkPerasParams cert` returns `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })` unconditionally.
5. The adversarial block at `pt` now has `weightBoostOfPoint snap pt = PerasWeight 15`.
6. Repeat for additional blocks on the adversarial fork; after `n` certificates, `totalWeightOfFragment adversarialFrag = blockCount + 15n`.
7. Once `totalWeightOfFragment adversarialFrag > totalWeightOfFragment honestFrag`, `preferCandidate` returns `ShouldSwitch`, and the honest node adopts the adversarial chain. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
