### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or semantic checks. Because this "validated" certificate is then stored in the `PerasCertDB` and used to boost a block's weight in chain selection, an unprivileged peer can craft a certificate pointing at any block on an adversarial fork and cause an honest node to prefer that fork over the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the gate that must authenticate a Peras certificate before it influences chain selection. The universal instance that covers all block types is:

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

No signature is verified, no round number is checked, no quorum proof is validated, and no check is made that the boosted block actually exists or belongs to a valid chain. The function wraps the raw peer-supplied `cert` directly into a `ValidatedPerasCert` and assigns it the full protocol-configured boost weight (`perasWeight params`).

This stub is the **only** implementation of `validatePerasCert` in the codebase (the `instance StandardHash blk => BlockSupportsPeras blk` is the universal instance). It is called in the inbound certificate processing path: [2](#0-1) 

Once a certificate passes this non-validation, it is stored in the `PerasCertDB` and triggers chain selection via `addPerasCertAsync` / `chainSelSync`: [3](#0-2) 

The accepted certificate's boosted block is then added to the `PerasWeightSnapshot`, which feeds directly into `weightBoostOfFragment` and `wsvTotalWeight` used by `WeightedSelectView.preferCandidate` during chain selection: [4](#0-3) 

The `wsvTotalWeight` is `BlockNo + weightBoost`, so a certificate boost of `perasWeight params` (a protocol-configured `Word64`) can make a shorter adversarial fork appear heavier than the honest chain.

The analogous flaw in the external report is `validatePerasCert` accepting any ratio without bounds checking; here the entire certificate body — including which block is being boosted — is accepted without any check.

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can send a crafted `PerasCert` whose `pcCertBoostedBlock` points to a block on an adversarial fork. Because `validatePerasCert` always returns `Right`, the certificate is stored and the adversarial block receives a `PerasWeight` boost equal to the full protocol-configured boost value. Chain selection (`preferCandidate`) then compares `wsvTotalWeight` values; if the boost is large enough relative to the honest chain's length advantage, the node switches to the adversarial fork. This constitutes:

- **Bypass of Peras certificate validation** enabling unauthorized certificate acceptance (Critical per scope).
- **Chain selection manipulation** causing an honest node to prefer a non-canonical chain (High per scope). [5](#0-4) 

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is already wired into the node and the `PerasCertDB` / chain-selection integration is active code (not behind a compile-time flag). The CHANGELOG confirms the integration is live: *"the candidate fragment is now selected based on its Peras weight"*. The TODO comment at the vulnerability site explicitly acknowledges the missing validation. Any peer connected via the object-diffusion protocol can send a `PerasCert` message with an arbitrary `pcCertBoostedBlock` field; no stake, key, or privilege is required. [1](#0-0) 

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that checks at minimum:

1. **Quorum proof**: the certificate must carry (or reference) a valid aggregate signature or quorum of individual votes from the registered committee for the claimed round.
2. **Round validity**: `pcCertRound` must fall within the current or recent Peras round window.
3. **Boosted block existence and era**: `pcCertBoostedBlock` must correspond to a block that is known, valid, and within the allowed age (`PerasBlockMinSlots` / `PerasCertMaxRounds`).
4. **No duplicate round**: a certificate for a round that already has a stored certificate should be rejected or deduplicated before chain selection is triggered.

Until the real validation is implemented, inbound certificates from untrusted peers should be rejected entirely (return `Left PerasValidationErr` unconditionally) rather than accepted unconditionally.

---

### Proof of Concept

1. Connect to a victim node that has Peras enabled via the object-diffusion mini-protocol.
2. Craft a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of a block on an adversarial fork>`.
3. Send the certificate to the victim node.
4. The node calls `validatePerasCert params cert` → returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is stored in `PerasCertDB`; `chainSelSync` fires `chainSelectionForBlock` for the boosted block.
6. `weightBoostOfFragment` adds `perasWeight params` to the adversarial fork's `wsvTotalWeight`.
7. `preferCandidate` in `WeightedSelectView` compares total weights; if the adversarial fork's boosted weight exceeds the honest chain's block-number-based weight, the node switches to the adversarial fork. [1](#0-0) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-1)
```haskell
{-# LANGUAGE GADTs #-}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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
