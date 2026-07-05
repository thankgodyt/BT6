### Title
Unconditional Peras Certificate Acceptance Enables Chain Selection Manipulation by Unprivileged Peer — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or semantic checks. This stub is wired directly into the production inbound certificate processing path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send a crafted `PerasCert` message over the object-diffusion mini-protocol; the certificate will be accepted, stored in the `PerasCertDB`, and used to boost the weight of an arbitrary block during chain selection, potentially causing the node to prefer a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The `BlockSupportsPeras` class defines `validatePerasCert` as the gate that must reject invalid certificates before they enter the node's state. The only instance in the codebase is a degenerate catch-all:

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

No signature is verified, no round-number bounds are checked, no boosted-block existence is confirmed, and no committee membership is validated. Every certificate, regardless of content, is stamped `ValidatedPerasCert` and returned as `Right`.

**Production wiring — stub is called on every inbound certificate from a peer:**

`makePerasCertPoolWriterFromChainDB` is explicitly documented as "for actual production use" and passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, because the stub always returns `Right`, unconditionally adds every certificate to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Chain selection impact — accepted certificate triggers fork switch:**

Once stored, a certificate is fed into `chainSelSync`, which triggers `chainSelectionForBlock` for the boosted block. The `vpcCertBoost` weight is incorporated into `WeightedSelectView.wsvWeightBoost`, which is summed with the block number to form `wsvTotalWeight`. Chain selection then prefers whichever fragment has the higher total weight:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
    ...
``` [5](#0-4) 

An attacker who sends a certificate naming a block on a minority fork, with a boost large enough to exceed the canonical chain's total weight, causes the honest node to switch to that fork.

---

### Impact Explanation

**Classification:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

Because `validatePerasCert` performs no checks, a single peer can inject a certificate that:
1. Names any block hash in the node's VolatileDB as the "boosted block."
2. Carries a `vpcCertBoost` equal to `perasWeight mkPerasParams` (a fixed placeholder value).
3. Causes `chainSelSync` to re-run chain selection with the fake boost applied, potentially switching the node to a shorter or minority fork.

Under Peras, the security parameter `k` is interpreted as a maximum rollback *weight*, not just block count. A fake certificate with boost ≥ `k` applied to a block on a fork that is only one block shorter than the canonical chain is sufficient to trigger a fork switch, rolling back up to `k` blocks of confirmed history. [6](#0-5) 

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol for Peras certificates is a public, peer-facing interface. Any node that connects to the victim and sends a well-formed CBOR-encoded `PerasCert` message (two fields: a round number and a block point) will have it accepted. No stake, no keys, and no prior relationship are required. The `PerasCert` wire format is simple:

```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2 <> encode pcCertRound <> encode pcCertBoostedBlock
``` [7](#0-6) 

An attacker only needs to know a valid block hash from the victim's VolatileDB (obtainable via ChainSync) to craft a targeted certificate.

---

### Recommendation

- **Short term:** Replace the stub `validatePerasCert` implementation with a real check that verifies: (a) the aggregate committee signature over the certificate fields, (b) that the round number is within the expected window, and (c) that the boosted block point is plausible. Until real validation is implemented, the inbound certificate path should reject all externally received certificates rather than accept them unconditionally.
- **Long term:** Resolve issue [#73](https://github.com/tweag/cardano-peras/issues/73) and [#120](https://github.com/tweag/cardano-peras/issues/120) before enabling the Peras object-diffusion mini-protocol on any network where nodes accept connections from untrusted peers. The `TODO: degenerate instance` comment must not be present in production-enabled code.

---

### Proof of Concept

1. Connect to a victim node that has the Peras object-diffusion mini-protocol enabled.
2. Obtain a block hash `H` from the victim's VolatileDB via ChainSync (e.g., the tip of a known minority fork one block shorter than the canonical chain).
3. Craft a CBOR message encoding `PerasCert { pcCertRound = <any fresh round>, pcCertBoostedBlock = BlockPoint <slot> H }`.
4. Send the message via the object-diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
6. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` is called.
7. `chainSelSync` runs `chainSelectionForBlock` for block `H`; the fake boost is added to `H`'s fragment weight via `weightBoostOfFragment`.
8. `preferCandidate` compares `wsvTotalWeight` of the current chain against the boosted fork and, if the boost exceeds the block-count deficit, returns `ShouldSwitch`, causing the node to roll back to the minority fork. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-37)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```
