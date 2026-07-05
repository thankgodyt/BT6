### Title
Unconditional `validatePerasCert` Acceptance Enables Forged Certificate Injection and Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation performs **zero validation** — it unconditionally returns `Right` for any certificate received from a peer. Because this is the only active instance and is wired into the production Peras certificate inbound pipeline, an unprivileged peer can inject a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock`, which will be stored in `PerasCertDB` and trigger chain selection with a full Peras weight boost applied to the attacker-chosen block.

---

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory gate for all inbound Peras certificates: [1](#0-0) 

The only active instance — the universal `StandardHash blk => BlockSupportsPeras blk` — implements this gate as an unconditional pass-through: [2](#0-1) 

No cryptographic signature is checked, no round-number bounds are enforced, and no boosted-block validity is confirmed. The `PerasCert` data type carries only `pcCertRound` and `pcCertBoostedBlock`: [3](#0-2) 

This stub is wired directly into the production certificate inbound pool writer used with the `ChainDB`: [4](#0-3) 

The `validatePerasCert mkPerasParams` call on line 103 is the only validation gate before the certificate is committed to `PerasCertDB` and forwarded to chain selection.

The `chainSelSync` handler for `ChainSelAddPerasCert` then uses the stored certificate to trigger `chainSelectionForBlock` for the attacker-specified `boostedBlock`: [5](#0-4) 

The only guards in `chainSelSync` are: (1) the boosted block's slot must be newer than the immutable tip, and (2) the boosted block must be present in `VolatileDB`. Neither guard requires the certificate to be cryptographically authentic. A peer that has already delivered a valid block header (which is independently validated) can then send a forged certificate boosting that block to manipulate chain selection weight.

The analogous partial-validation gap exists in `validatePerasVote`, which checks only that the claimed voter ID exists in the stake distribution but performs no signature verification over the vote content: [6](#0-5) 

This means an attacker can also impersonate any registered stake pool to forge votes, accumulate quorum, and generate a synthetic certificate — all without holding the corresponding signing key.

---

### Impact Explanation

Peras certificates apply a configurable weight boost (`perasWeight`) to a block during chain selection. By injecting a forged certificate pointing to a block on a competing fork, an unprivileged peer can cause an honest node to compute that fork as heavier than the canonical chain and switch to it. This is a **chain selection manipulation** attack: the node is made to prefer a non-canonical, potentially adversarially-controlled chain beyond the intended security assumptions of the Ouroboros protocol. The impact maps to: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The attack requires only that the adversary: (1) be a connected peer, (2) have previously delivered a block that is present in the victim's `VolatileDB`, and (3) send a `PerasCert` over the Peras object-diffusion mini-protocol pointing to that block. No key material, stake, or privileged access is needed. The production code path is active whenever the Peras diffusion layer is enabled. Likelihood is **High** given the zero-barrier entry path.

---

### Recommendation

Replace the unconditional stub with a real implementation that:
1. Verifies the aggregate cryptographic signature embedded in the certificate against the claimed voter set and the `electionId`/`candidate` fields (analogous to `implVerifyCert` in `EveryoneVotes` or `WFALS`).
2. Validates that `pcCertRound` falls within the expected active round window derived from the current ledger state.
3. Validates that `pcCertBoostedBlock` refers to a block that is a plausible candidate for the claimed round (slot range check).

Until a real instance is available, the inbound certificate pipeline should reject all certificates at the `processVotes`/`processCerts` boundary rather than accepting them unconditionally.

---

### Proof of Concept

1. Attacker connects as a peer and delivers block `B` at slot `s` (passes normal header validation).
2. Block `B` is stored in the victim's `VolatileDB`.
3. Attacker constructs `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf B }` with no valid signature.
4. Attacker sends this certificate via the Peras cert diffusion mini-protocol.
5. `makePerasCertPoolWriterFromChainDB` calls `processCerts … (validatePerasCert mkPerasParams) …`.
6. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally.
7. Certificate is stored in `PerasCertDB`; `chainSelSync` fires `chainSelectionForBlock` for `B`.
8. Chain selection now treats the fork containing `B` as having additional Peras weight, potentially causing the node to switch away from the canonical chain. [7](#0-6) [4](#0-3) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-544)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
 where
  tracer :: Tracer m (TraceAddPerasCertEvent blk)
  tracer = TraceAddPerasCertEvent >$< cdbTracer

  certRound :: PerasRoundNo
  certRound = getPerasCertRound cert

  boostedBlock :: Point blk
  boostedBlock = getPerasCertBoostedBlock cert
```
