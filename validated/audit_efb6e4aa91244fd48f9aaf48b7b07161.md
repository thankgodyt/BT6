### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the sole production instance covering all block types — implements `validatePerasCert` as an unconditional `Right`, accepting every inbound Peras certificate without performing any cryptographic or structural check. An unprivileged peer can submit a crafted certificate boosting any block already present in the VolatileDB, causing the receiving node to artificially inflate that block's chain-selection weight and potentially switch to a non-canonical fork.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal instance `instance StandardHash blk => BlockSupportsPeras blk` (lines 318–389) is the only `BlockSupportsPeras` instance in the codebase. Its `validatePerasCert` implementation is:

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

This unconditionally returns `Right (ValidatedPerasCert …)` for **every** certificate, regardless of:
- Whether the certificate carries a valid aggregate BLS signature over the claimed quorum of votes.
- Whether the claimed voters actually reached quorum.
- Whether the round number is consistent with the current epoch.
- Whether the boosted block point is on any honest chain.

The `PerasValidationErr` data type is also a single-constructor stub (`= PerasValidationErr`) with no error variants, confirming that no real error path exists.

The same instance's `validatePerasVote` (lines 363–371) only checks that the voter ID appears in the stake distribution map; it does **not** verify the vote signature. This means forged votes from any registered voter can be injected to manufacture a quorum, which then triggers `forgePerasCert` (lines 376–385) — itself also a stub that returns `Right` unconditionally — producing a `ValidatedPerasCert` that is fed into `addPerasCertAsync`. [1](#0-0) 

The resulting `ValidatedPerasCert` is consumed by `chainSelSync` in `ChainSel.hs` (lines 483–532), which adds it to the `PerasCertDB` and triggers chain selection for the boosted block, applying `vpcCertBoost = perasWeight params` as additional weight to that block's fragment via `weightBoostOfFragment` / `totalWeightOfFragment`. [2](#0-1) 

The weight boost directly affects `takeVolatileSuffix` and the chain comparison logic in `Peras.Weight`, which computes `totalWeightOfFragment` as block-count plus accumulated Peras boosts. [3](#0-2) 

---

### Impact Explanation

**High — Chain selection manipulation via crafted Peras certificates.**

A peer that submits a certificate referencing a block already in the VolatileDB causes the honest node to boost that block's weight by `perasWeight params` without any quorum or signature check. If the boosted block is on a minority fork, the node may switch to that fork, diverging from the canonical chain. Because the boost is durable (stored in `PerasCertDB` and reflected in `PerasWeightSnapshot`), the divergence persists until the boosted block becomes immutable or is pruned. This satisfies the "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" criterion. [4](#0-3) 

---

### Likelihood Explanation

**Medium.** The Peras miniprotocol is under active development and the degenerate instance is explicitly marked as a compilation placeholder (issue #73, #120). However, the instance is already wired into the live `ObjectPool` vote/cert diffusion path (`makePerasVotePoolWriterFromChainDB`, `makePerasVotePoolWriterFromVoteDB`) and into `ChainDB.addPerasCertAsync`. Any peer that can reach the Peras object-diffusion miniprotocol endpoint can submit a crafted certificate with no privilege requirement. [5](#0-4) 

---

### Recommendation

1. **Replace the stub `validatePerasCert`** with a real implementation that verifies the aggregate BLS signature over the claimed voter set, checks that the voter set meets the quorum threshold, and validates the round number against the current epoch.
2. **Replace the stub `validatePerasVote`** with an implementation that verifies the individual vote signature before accepting the vote into the pool.
3. Until real validation is implemented, **gate the Peras cert/vote miniprotocol endpoints** so they are unreachable from untrusted peers (e.g., behind a feature flag that is disabled by default on mainnet).
4. Promote `PerasValidationErr` from a single-constructor stub to a proper sum type enumerating all possible validation failures, so that future validation logic has typed error paths. [6](#0-5) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a node running the Peras object-diffusion miniprotocol.
2. Attacker observes (via ChainSync) a block `B` on a minority fork that is present in the node's VolatileDB.
3. Attacker constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(B) }` with arbitrary round `r` and no valid signature.
4. Attacker submits the certificate via the Peras cert diffusion channel, which calls `validatePerasCert` on the node.
5. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
6. The `ValidatedPerasCert` is passed to `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event.
7. `chainSelSync` adds the cert to `PerasCertDB`, looks up block `B` in the VolatileDB (succeeds), and calls `chainSelectionForBlock` for `B`.
8. `totalWeightOfFragment` now includes `perasWeight params` for `B`'s fragment, potentially making it heavier than the current selection.
9. The node switches to the minority fork containing `B`.

**Key code path:**

```
peer submits PerasCert
  → validatePerasCert (SupportsPeras.hs:353) → always Right
  → addPerasCertAsync (ChainDB/API.hs:441)
  → chainSelSync / ChainSelAddPerasCert (ChainSel.hs:483)
  → PerasCertDB.addCert + chainSelectionForBlock (ChainSel.hs:495,531)
  → totalWeightOfFragment inflated (Peras/Weight.hs:313)
  → node adopts minority fork
``` [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
