### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Unauthorized Chain-Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance is a stub that always returns `Right`, performing zero validation. Because Peras certificates directly control the `PerasWeightSnapshot` used in chain selection, an unprivileged peer can inject a crafted certificate that boosts any block's weight, causing an honest node to prefer and switch to an adversarial chain. This is the direct analog of the LP-deposit "missing minimum return check" class: just as the LP vault lacked a guard on the output amount, the Peras certificate path lacks any guard on the certificate's authenticity, allowing external state manipulation to produce an outcome the node never intended to accept.

---

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the mandatory gate before a certificate may influence chain selection. The only instance in the codebase is a universal one covering every `StandardHash blk` type:

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

No more-specific instance exists for Cardano blocks; Haskell resolves this universal instance for all production block types. The function ignores every field of `cert` and unconditionally wraps it in `Right ValidatedPerasCert` with the full configured boost weight.

The downstream chain-selection path is:

1. A peer delivers a `ValidatedPerasCert` (produced by the stub above).
2. `chainSelSync` calls `PerasCertDB.addCert`, which stores the certificate and updates the `PerasWeightSnapshot`. [2](#0-1) 

3. `preferAnchoredCandidate` calls `weightedSelectView`, which calls `weightBoostOfFragment` against the now-poisoned snapshot. [3](#0-2) 

4. `wsvTotalWeight` sums `BlockNo` and `wsvWeightBoost`; a large injected boost makes the adversarial fragment appear heavier than the honest chain. [4](#0-3) 

5. `chainSelection` selects the adversarial candidate and the node switches forks. [5](#0-4) 

The secondary stub `validatePerasVote` also skips signature verification, accepting any vote whose `PerasVoterId` appears in the stake distribution. This means an attacker can forge votes for every eligible voter, manufacture a quorum, and have the node itself forge the certificate — again bypassing `validatePerasCert`. [6](#0-5) 

**Analog mapping to the LP-deposit report:**

| LP Deposit (M-01) | Peras Certificate |
|---|---|
| `balanceFactor` computed from TVL that a strategist can change | `wsvTotalWeight` computed from `PerasWeightSnapshot` that a peer can poison |
| No minimum LP-out check | No certificate authenticity check (`validatePerasCert` always `Right`) |
| User receives fewer LP tokens than intended | Node switches to adversarial chain it never intended to adopt |

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

- Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialPoint }`.
- Deliver it via the Peras certificate mini-protocol.
- `validatePerasCert` accepts it unconditionally; the full `perasWeight` boost is recorded in the `PerasWeightSnapshot`.
- Chain selection now sees the adversarial fork as heavier than the honest chain by `perasWeight` units.
- The node rolls back up to `k` weight of honest blocks and adopts the adversarial chain.

This constitutes a **Critical** consensus-safety failure: bypass of Peras certificate checks enabling unauthorized certificate acceptance and irreversible divergence from the honest chain.

---

### Likelihood Explanation

- Peras is currently disabled by default (`isEmptyPerasWeightSnapshot` short-circuits the weighted path), so the attack surface is inactive on mainnet today.
- The code is in production files, not test stubs, and is gated only by a feature flag. Once Peras is enabled on any network (testnet or mainnet), the vulnerability is immediately reachable by any connected peer with no special privileges, keys, or stake.
- The exploit requires only constructing a valid-looking `PerasCert` struct — no cryptographic material is needed because no cryptographic check is performed.

---

### Recommendation

1. **Implement `validatePerasCert`** to verify: (a) the certificate's aggregate signature over the boosted block and round number, (b) that the signing committee was legitimately elected for that round, and (c) that the boosted block's slot falls within the valid voting window for the round.
2. **Implement `validatePerasVote`** to verify the individual vote's cryptographic signature before counting its stake toward quorum.
3. Until real validation is in place, **gate the Peras code path** so that `addPerasCertAsync` rejects any certificate that does not pass a non-trivial validation predicate, rather than relying on the stub returning `Right`.

---

### Proof of Concept

```
Setup: private testnet with Peras enabled (eraPerasRoundLength set).

1. Attacker node A has a fork F_adv that is k blocks shorter (less weight)
   than the honest chain F_hon held by victim node V.

2. A constructs:
     cert = PerasCert { pcCertRound    = currentRound
                      , pcCertBoostedBlock = tip(F_adv) }

3. A calls addPerasCertAsync on V (via the Peras cert diffusion protocol).

4. V calls validatePerasCert cert → Right (ValidatedPerasCert cert perasWeight).
   (No signature, no round eligibility, no block-on-chain check performed.)

5. V's PerasWeightSnapshot now contains:
     tip(F_adv) → PerasWeight B   where B = perasWeight params

6. preferAnchoredCandidate computes:
     wsvTotalWeight(F_adv suffix) = blockNo(tip F_adv) + B
     wsvTotalWeight(F_hon suffix) = blockNo(tip F_hon)
   If B > (blockNo(tip F_hon) - blockNo(tip F_adv)), F_adv wins.

7. V rolls back F_hon and adopts F_adv — consensus safety violated.
``` [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-61)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
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
