### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Unprivileged Chain-Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the production `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or semantic validation. Because Peras certificates are the mechanism by which blocks receive weight boosts in chain selection, any peer that can deliver a certificate object to the node can arbitrarily inflate the `PerasWeightSnapshot` for any block on any chain — including a non-canonical adversarial fork — causing the node to prefer that fork over the honest chain.

---

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the gate that must be passed before a certificate is treated as `ValidatedPerasCert` and handed to `addPerasCertAsync`. The sole production instance of this class is:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

Every certificate, regardless of its cryptographic content, round number, target block, or committee membership, is immediately wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost. [1](#0-0) 

The resulting `ValidatedPerasCert` is inserted into the `PerasWeightSnapshot` via `addPerasCertAsync`:

```haskell
, addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [2](#0-1) 

Chain selection then reads the snapshot atomically and uses it to compare candidate chains:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [3](#0-2) 

The `preferCandidate` comparison adds `wsvWeightBoost` (derived from the snapshot) to the block number when deciding whether to switch chains:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

The analog to the external report is direct: just as `setMarketFeePercent` is a mutable parameter read at execution time that a privileged actor can change to steal funds, the `PerasWeightSnapshot` is a mutable parameter read at chain-selection time that an attacker can change — by injecting unvalidated certificates — to make the node prefer a non-canonical chain. The external report's fix was to let the caller commit to the expected fee; here the equivalent fix is to actually validate the certificate before accepting it.

---

### Impact Explanation

An unprivileged peer that can deliver a `PerasCert` object to the node (via the Peras certificate or vote mini-protocol) can boost the `PerasWeightSnapshot` of any block on any fork by the full `perasWeight` value. If the adversarial fork's boosted total weight exceeds the honest chain's total weight, `preferCandidate` returns `ShouldSwitch` and the node rolls back to the adversarial fork. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, potentially adversarial chain beyond the intended security assumptions of Ouroboros Peras.

---

### Likelihood Explanation

The attack requires only that the Peras certificate or vote diffusion mini-protocol is active (i.e., Peras is enabled on the network). No stake, no keys, and no special privileges are needed. The attacker constructs a `PerasCert` with `pcCertBoostedBlock` pointing to a block on their preferred fork and delivers it; the stub accepts it unconditionally. The `addPerasCertAsync` path then triggers a chain-selection re-evaluation with the inflated weight.

---

### Recommendation

1. Implement real cryptographic and semantic validation inside `validatePerasCert`: verify committee membership, VRF/KES signatures, round number bounds, and that the boosted block is within the valid Peras window.
2. Until a real implementation exists, gate `addPerasCertAsync` behind a feature flag so that the stub cannot be reached from the network layer.
3. Apply the same scrutiny to `validatePerasVote`, which follows the same stub pattern and feeds into certificate forging via `updatePerasRoundVoteStates`.

---

### Proof of Concept

```
Attacker node A                          Honest node H
─────────────────────────────────────────────────────
1. A holds a valid adversarial fork F'
   (shorter than honest chain F by N blocks)

2. A crafts PerasCert { pcCertBoostedBlock = tip(F') }
   and sends it to H via the Peras cert mini-protocol.

3. H calls validatePerasCert params cert
   → always returns Right (ValidatedPerasCert { vpcCertBoost = perasWeight })

4. H calls addPerasCertAsync cert
   → PerasWeightSnapshot[tip(F')] += perasWeight

5. H runs chainSelectionForBlock:
   totalWeight(F') = blockNo(F') + perasWeight
   totalWeight(F)  = blockNo(F)
   If perasWeight > N, then totalWeight(F') > totalWeight(F)
   → preferCandidate returns ShouldSwitch
   → H rolls back to F'
```

The root cause is at: [5](#0-4) 

with the chain-selection consequence visible at: [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
