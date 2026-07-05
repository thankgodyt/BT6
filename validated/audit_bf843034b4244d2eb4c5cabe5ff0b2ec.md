### Title
Peras Certificate Validation Bypass via No-Op `validatePerasCert` Allows Unprivileged Chain-Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default catch-all `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or semantic validation. An unprivileged peer can craft and submit an arbitrary `PerasCert` via the object-diffusion mini-protocol; the certificate is stamped as `ValidatedPerasCert` and stored in the `PerasCertDB`, where it inflates the Peras weight of any chosen block. Because chain selection now uses total Peras weight rather than chain length, the attacker can make an honest node prefer a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op.**

`BlockSupportsPeras.hs` defines a universal overlapping instance for every `StandardHash blk`:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

The function ignores every field of `cert` and returns `Right` unconditionally. No round-number bounds, no boosted-block existence check, no quorum proof, and no cryptographic signature are verified.

**Inbound path — object-diffusion mini-protocol for certificates.**

Inbound Peras certificates arrive through `ObjectPool/PerasCert.hs`, which calls `validatePerasCert` before forwarding to `ChainDB.addPerasCertAsync`. Because `validatePerasCert` always succeeds, every crafted certificate clears this gate. [2](#0-1) 

**Chain-selection impact — weight boost applied unconditionally.**

`ChainSel.hs` calls `weightBoostOfFragment` / `totalWeightOfFragment` from `PerasWeightSnapshot` to compare candidate fragments. A `ValidatedPerasCert` accepted from the attacker is stored in `PerasCertDB` and reflected in the snapshot, directly inflating the weight of the attacker-chosen block. [3](#0-2) 

`WeightedSelectView` compares `wsvTotalWeight` (block-number + weight boost), so a sufficiently large forged boost can make a shorter adversarial fork outweigh the honest chain. [4](#0-3) 

**Secondary surface — `validatePerasVote` skips signature verification.**

The same default instance's `validatePerasVote` only checks that the claimed voter ID appears in the stake distribution; it performs no cryptographic verification of the vote body. An attacker who knows any committee member's public `PerasVoterId` (which is public on-chain) can forge votes for that member, accumulate stake toward quorum, and trigger `forgePerasCert`, which also performs no validation. [5](#0-4) 

---

### Impact Explanation

**Severity: High → Critical (Peras-enabled deployment).**

When Peras is enabled (private testnet or future mainnet activation), an unprivileged peer can:

1. Craft a `PerasCert` pointing to any block on a minority fork.
2. Submit it via the object-diffusion protocol; `validatePerasCert` accepts it unconditionally.
3. The certificate is stored and its boost is added to the fork's weight.
4. `preferAnchoredCandidate` / `WeightedSelectView` now ranks the adversarial fork above the honest chain.
5. The node switches to the adversarial fork — a chain-selection safety failure.

This matches the allowed impact: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance"* and *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

- **Peras is disabled by default** on mainnet today; the CHANGELOG explicitly notes "if Peras is disabled (which is the default), there is no observable difference."
- However, the code is compiled into every node binary and the object-diffusion protocol handler is wired in. Any private testnet or future mainnet activation immediately exposes the vulnerability.
- No privileged access, no key material, and no stake are required. The attacker only needs a peer connection and knowledge of any block hash to boost.
- The TODO comments and linked GitHub issue (`tweag/cardano-peras#120`) confirm the incomplete validation is a known, unresolved gap — not an intentional design choice.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the certificate's cryptographic proof of quorum (committee signatures / VRF outputs), the round number is within the valid window, and the boosted block exists and is within the volatile window.
2. **Implement real vote validation** in `validatePerasVote`: verify the vote's cryptographic signature against the committee member's registered key, not merely the presence of the voter ID in the stake distribution.
3. Until (1) and (2) are complete, **gate the object-diffusion handlers** so that inbound Peras certificates and votes are silently dropped (or the protocol is not advertised) when Peras is not fully activated, preventing the no-op validation path from being reachable.

---

### Proof of Concept

**Private-testnet sequence (Peras enabled):**

1. Start two nodes A (honest) and B (attacker) on a private testnet with Peras enabled.
2. Node A's current chain tip is block `H` at height 100 with total weight 100.
3. Attacker B has a fork `F` at height 99 (weight 99 — normally not preferred).
4. B constructs a `PerasCert { pcCertRound = 1, pcCertBoostedBlock = pointOf(F_tip) }` with no valid quorum proof.
5. B sends this certificate to A via the Peras certificate object-diffusion mini-protocol.
6. A's `validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
7. The certificate is stored; `weightBoostOfFragment` adds `perasWeight` (e.g., 15) to fork F's weight → total weight 114 > 100.
8. `preferAnchoredCandidate` returns `ShouldSwitch`; node A rolls back to fork F.
9. Node A now follows the adversarial chain, diverging from the honest network. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-389)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-10)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
-- certificates from the 'PerasCertDB' (or the 'ChainDB' which is wrapping the
-- 'PerasCertDB').
module Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert
  ( makePerasCertPoolReaderFromCertDB
  , makePerasCertPoolWriterFromCertDB
  , makePerasCertPoolReaderFromChainDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L774-778)
```haskell
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-268)
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
