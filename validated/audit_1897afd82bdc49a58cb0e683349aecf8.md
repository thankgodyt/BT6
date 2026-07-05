### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance — which is the only instance in production for all block types — implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate it receives, assigning the full configured `perasWeight` boost without performing any cryptographic or semantic validation. When Peras is enabled, an unprivileged peer can send a crafted certificate over the object-diffusion mini-protocol, have it accepted as `ValidatedPerasCert`, and trigger chain selection for an arbitrary block in the VolatileDB with an artificially inflated weight, causing the node to prefer a non-canonical adversarial chain over the honest chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that converts a raw `PerasCert` into a `ValidatedPerasCert`. The only concrete instance in the codebase is the blanket default:

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

This stub skips all validation — no quorum check, no signature verification, no round-number validity, no check that the boosted block was actually elected. Every certificate, regardless of origin or content, is accepted and assigned the maximum configured weight boost.

The `addPerasCertAsync` path in `ChainSel.hs` then uses this `ValidatedPerasCert` directly to trigger chain selection for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [2](#0-1) 

Chain selection then compares candidates using `preferAnchoredCandidate`, which incorporates the `PerasWeightSnapshot` — the weight boost from the fraudulent certificate is now part of the comparison: [3](#0-2) 

The `PerasWeightSnapshot` is populated from the `PerasCertDB`, which stores the fraudulent certificate without any re-validation: [4](#0-3) 

The `getPerasCertInBlock _ = Nothing` stub confirms no Cardano-specific override exists: [5](#0-4) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can send a crafted `PerasCert` via the object-diffusion protocol. Because `validatePerasCert` always returns `Right`, the certificate is stored as `ValidatedPerasCert` with the full `perasWeight` boost. Chain selection then uses this fraudulent weight when comparing candidate fragments. If the attacker boosts a block on a valid-but-adversarial fork that is otherwise shorter than the honest chain, the node will switch to that fork — a chain-selection error that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended Praos security assumptions.

This matches the allowed impact: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

**Precondition**: Peras must be enabled via the `rnFeatureFlags` field in `RunNodeArgs`. It is disabled by default. On any private testnet or future mainnet deployment where Peras is activated, the attack is immediately reachable by any connected peer with no privileged access. The attacker only needs to know a block hash present in the target node's VolatileDB (observable via ChainSync headers) and send a single crafted certificate message. No keys, stake, or prior authentication are required.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that verifies:
1. The certificate's aggregate BLS/KES signature against the committee's public keys for the claimed round.
2. That the number of valid signers meets the quorum threshold.
3. That the boosted block's slot falls within the valid range for the claimed Peras round.
4. That the round number is not a replay of an already-processed round.

Until a correct implementation exists, the Peras feature flag must remain disabled in all deployments, and the stub must not be reachable from any network-facing code path.

---

### Proof of Concept

1. Enable Peras on a private two-node testnet (node A = honest, node B = attacker).
2. Let node A sync to tip `T` on the honest chain.
3. Attacker (node B) mines a valid but shorter fork `F` branching from a point within `k` blocks of `T`, with tip block hash `H_adv` present in node A's VolatileDB.
4. Node B sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = H_adv }` to node A via the object-diffusion protocol.
5. Node A calls `validatePerasCert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. `addPerasCertAsync` stores the cert and calls `chainSelectionForBlock` for `H_adv`.
7. Chain selection computes `totalWeightOfFragment` for fork `F`, which now includes the fraudulent boost, making it heavier than the honest chain.
8. Node A switches to fork `F`, diverging from the honest chain. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1141-1144)
```haskell

  sortCandidates ::
    [(ChainDiff (Header blk), ReasonForSwitch' blk)] -> [(ChainDiff (Header blk), ReasonForSwitch' blk)]
  sortCandidates = sortBy ((flip $ compareChainDiffs bcfg weights curChain) `on` fst)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
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
