### Title
Peras Certificate Validation Unconditionally Returns `Right`, Bypassing All Cryptographic Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The catch-all `BlockSupportsPeras` instance, which applies to **all** block types, implements `validatePerasCert` as a hardcoded stub that always returns `Right` — accepting every certificate unconditionally, without any cryptographic or structural verification. This is the direct analog of the external report's pattern: a critical bound/check is set to an incorrect constant (here, "always valid" instead of "always maximum input"), making the check permanently ineffective. Any unprivileged peer that can deliver a crafted `PerasCert` object to a Peras-enabled node will have it accepted and applied to chain selection.

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate and vote validation. Its `validatePerasCert` method is the gatekeeper that must verify a certificate's cryptographic integrity before the certificate is stored and used to boost a block's chain-selection weight.

The production source file contains a single, universally-applicable instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
  ...
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

Because this is a catch-all instance (`StandardHash blk => BlockSupportsPeras blk`), it is the only instance in scope for every concrete block type, including `CardanoBlock`. There is no override with real cryptographic checks. The function ignores `params` entirely for validation purposes and unconditionally wraps the caller-supplied `cert` in a `ValidatedPerasCert` carrying the full configured `perasWeight` boost.

The same pattern applies to `validatePerasVote`, which skips signature verification:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [2](#0-1) 

A `ValidatedPerasCert` produced by `validatePerasCert` is consumed directly by `addPerasCertAsync` in the ChainDB API, which stores it in the `PerasCertDB` and triggers chain selection for the boosted block: [3](#0-2) 

Chain selection then uses `wsvTotalWeight`, which adds the certificate's `vpcCertBoost` to the block's weight, potentially causing the node to prefer a chain it would otherwise reject: [4](#0-3) 

The `perasWeight` default is `PerasWeight 15`, which is a substantial boost relative to the security parameter `k = 2160` in terms of chain-selection arithmetic: [5](#0-4) 

### Impact Explanation

When Peras is enabled, an unprivileged peer can craft a `PerasCert` claiming any block point as the boosted block and submit it to the node. Because `validatePerasCert` always returns `Right`, the certificate is stored and applied to chain selection without any cryptographic proof that a quorum of honest committee members actually voted for that block. The attacker can therefore:

1. Artificially boost a minority fork by `perasWeight` (default 15) units, potentially making it heavier than the honest chain.
2. Cause the node to switch to an adversarially-controlled chain that it would otherwise reject under the standard longest-chain rule.
3. Repeat across multiple rounds to accumulate weight advantage.

This is a **bypass of Peras certificate verification** enabling unauthorized chain selection manipulation — matching the "Critical. Bypass of certificate/vote verification checks that enables unauthorized certificate acceptance" impact category.

### Likelihood Explanation

Peras is not enabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference` — CHANGELOG). However, the vulnerability is fully reachable the moment any operator enables Peras. The attack requires no special privileges, no key compromise, and no stake: any peer that can deliver a network message containing a `PerasCert` can exploit this. The entry path is the existing Peras certificate diffusion channel (`addPerasCertAsync`), which is a standard part of the node's public API surface.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real cryptographic check that:
1. Verifies the aggregate BLS signature over the certificate's election ID and candidate block using the committee's aggregate verification key.
2. Confirms the certificate references a valid round and a block within the allowed age window (`perasCertMaxRounds`).
3. Confirms the total stake of the signers meets the quorum threshold (`stakeAboveThreshold`).

Until a real implementation is available, the `addPerasCertAsync` path should refuse to process any certificate when Peras is enabled, or the Peras feature flag should be enforced to remain disabled in all production builds until this method is implemented.

### Proof of Concept

```
1. Enable Peras on a test node (set the Peras feature flag).
2. Craft a PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <point of a minority-fork block> }.
3. Wrap it in a ValidatedPerasCert by calling validatePerasCert with any PerasParams.
   -- Returns Right immediately; no signature checked.
4. Submit via addPerasCertAsync to the node's ChainDB.
5. Observe: chainSelectionForBlock is triggered for the boosted block.
6. The minority-fork block now carries +15 weight in wsvTotalWeight.
7. If the honest chain's lead is < 15 blocks, the node switches to the adversarial fork.
``` [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
