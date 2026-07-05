After thorough investigation of the codebase, I found a structurally direct analog to the external report's vulnerability class.

---

### Title
Global `BlockSupportsPeras` Default Instance Accepts Any Peras Certificate Without Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The external report describes contracts inheriting `Rescuable` without overriding it to exclude protected tokens — a "default implementation too permissive, not restricted for specific contexts" pattern. In Ouroboros Consensus, the global `BlockSupportsPeras` instance (which applies to **all** block types including the production `HardForkBlock`) implements `validatePerasCert` as an unconditional `Right` — accepting every Peras certificate without any cryptographic or semantic check. No more-specific instance overrides this for `HardForkBlock`. An unprivileged peer can therefore inject crafted Peras certificates that are accepted as valid, adding arbitrary weight boosts to blocks and manipulating chain selection.

### Finding Description

**Root cause — global instance, no override:** [1](#0-0) 

The instance at line 320 is declared as:
```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
  getPerasCertInBlock _ = Nothing
```

`validatePerasCert` performs **zero** checks — no signature verification, no quorum check, no round-number sanity — and unconditionally returns `Right` with the full configured `perasWeight`. This is the direct analog of `Rescuable` not being overridden: the default is maximally permissive and no production block type overrides it.

**No specific instance for `HardForkBlock`:**

The CHANGELOG records `LedgerSupportsPeras` instances for `HardForkBlock` and Shelley, but no `BlockSupportsPeras` override exists for either. The global catch-all instance therefore governs the production Cardano block type.

**Chain-selection impact path:**

Accepted certificates are stored in the `PerasCertDB` and converted into a `PerasWeightSnapshot`. `preferAnchoredCandidate` and `compareAnchoredFragments` branch on whether the snapshot is non-empty: [2](#0-1) 

When the snapshot is non-empty (i.e., after any certificate is accepted), chain selection switches from pure block-number comparison to weighted comparison. A fake certificate boosting an attacker-controlled block can therefore make an honest node prefer a non-canonical chain.

**The `checkPreferTheirsOverOurs` bypass (secondary):**

The ChainSync client's beyond-forecast-horizon check hardcodes `emptyPerasWeightSnapshot`, ignoring real weights: [3](#0-2) 

This means even if a node has accepted boosted-block certificates, the disconnect guard for sparse candidates does not account for them, compounding the chain-selection inconsistency.

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker sends a crafted `PerasCert` claiming to boost a block on a minority fork. `validatePerasCert` accepts it unconditionally. The resulting `PerasWeightSnapshot` causes `preferAnchoredCandidate` to score the attacker's fork higher than the honest chain, triggering a chain switch. Because the weight boost is `perasWeight params` (a protocol-configured constant, not zero), the effect is proportional to the configured Peras weight.

### Likelihood Explanation

**Medium.** The Peras certificate diffusion infrastructure (`ObjectDiffusion` for votes and certificates) is present in production files and actively being wired up (CHANGELOG entries confirm ongoing integration). The global instance is in a production module, not a test module. The attack is reachable as soon as the Peras certificate diffusion miniprotocol is enabled on a live network. The TODO comment acknowledges the incompleteness but does not gate the code behind a feature flag or compile-time guard.

### Recommendation

- **Short term:** Add an `{-# OVERLAPPING #-}` or dedicated `BlockSupportsPeras (HardForkBlock xs)` instance that delegates `validatePerasCert` to the per-era implementation and rejects certificates for eras that do not support Peras. Mirror the pattern already used for `LedgerSupportsPeras (HardForkBlock xs)`.
- **Short term:** Gate the global degenerate instance behind a compile-time flag or restrict it to test-only modules so it cannot be accidentally used in production.
- **Long term:** Before enabling Peras certificate diffusion on any live network, ensure every reachable call site of `validatePerasCert` is covered by a properly validated instance, analogous to how `additionalEnvelopeChecks` is overridden per era in `ValidateEnvelope`.

### Proof of Concept

1. Connect to a node with Peras certificate diffusion enabled.
2. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a minority fork controlled by the attacker.
3. Send the certificate via the Peras certificate diffusion miniprotocol.
4. The node calls `validatePerasCert` (global instance) → unconditional `Right`.
5. The certificate is stored; `PerasWeightSnapshot` becomes non-empty with the attacker's block boosted by `perasWeight params`.
6. On the next chain-selection event, `preferAnchoredCandidate` takes the weighted branch and scores the attacker's fork higher than the honest chain, causing the node to switch. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1838-1851)
```haskell
      shouldSwitch $
        preferAnchoredCandidate
          (configBlock cfg)
          -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
          emptyPerasWeightSnapshot
          ourFrag
          theirFrag =
        pure ()
    | otherwise =
        throwSTM $
          CandidateTooSparse
            mostRecentIntersection
            (ourTipFromChain ourFrag)
            (theirTipFromChain theirFrag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L55-57)
```haskell
-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```
