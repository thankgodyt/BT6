### Title
Missing Peras Certificate Validation Allows Arbitrary Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or semantic validation. This stub is wired directly into the production certificate ingestion path. Any unprivileged peer can therefore inject an arbitrary `PerasCert` that boosts any block of their choosing, manipulating the `PerasWeightSnapshot` used by chain selection and potentially causing the node to prefer a non-canonical or adversarially-controlled chain.

---

### Finding Description

**Root cause — stub validation that always succeeds:**

The universal `BlockSupportsPeras` instance (explicitly labelled "degenerate instance for all blks to get things to compile") implements `validatePerasCert` as an unconditional `Right`:

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

No signature, quorum, committee membership, round-number, or boosted-block check is performed. Every certificate, regardless of content, is accepted.

**Production ingestion path:**

`makePerasCertPoolWriterFromChainDB` — the production writer used for inbound peer certificates — passes this stub directly to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls the validator on every new inbound certificate and, if all pass (they always do), timestamps and forwards them to `addCert`: [3](#0-2) 

**Chain selection side-effect:**

Accepted certificates are forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: the certificate is stored in `PerasCertDB`, and `chainSelectionForBlock` is triggered for the boosted block: [4](#0-3) 

The `PerasWeightSnapshot` is then rebuilt from all stored certificates and used in `compareAnchoredFragments` / `weightedSelectView` to decide which chain is preferred: [5](#0-4) [6](#0-5) 

**Analogy to the external report:**

The external report describes a missing `default_dict_finalize` constraint: the `prev_value` of the first dictionary entry is never asserted to equal the expected default, so a malicious prover can set it to any value and corrupt subsequent reads. Here, the missing constraint is the certificate validation itself: the `validatePerasCert` function is supposed to assert cryptographic and protocol-level properties of the certificate, but the assertion is entirely absent. In both cases, an attacker-controlled value (a dictionary entry / a certificate) passes through a validation gate that performs no actual checking, and the unchecked value then influences security-critical state (dictionary reads / chain selection weights).

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to a block on an adversarial fork. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and its weight boost is applied to the target block. If the boost (`perasWeight`, currently `PerasWeight 15`) is sufficient to make the adversarial fork heavier than the honest chain, the node switches to the adversarial fork. This constitutes a **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain**, matching the High/Critical impact categories in scope.

---

### Likelihood Explanation

Any peer connected via the Peras certificate object-diffusion mini-protocol can exploit this. No stake, no keys, and no prior knowledge of the chain state beyond the target block's point are required. The attacker only needs to craft a valid CBOR-encoded `PerasCert` structure (two fields: `pcCertRound` and `pcCertBoostedBlock`) and send it over the wire.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The aggregate vote signature over the certificate's `(electionId, candidate)` pair.
2. That the voters form a valid quorum (total stake ≥ threshold) drawn from the correct committee for the claimed round.
3. That `pcCertBoostedBlock` refers to a block that is eligible to be boosted (age ≥ `perasBlockMinSlots`, on a valid chain).
4. That `pcCertRound` is within the acceptable window (not expired per `perasCertMaxRounds`).

Until the real implementation is in place, the node should refuse to accept inbound Peras certificates from peers (i.e., the object-diffusion handler should not be activated) rather than silently accepting all of them.

---

### Proof of Concept

1. Connect to a target node as a Peras certificate diffusion peer.
2. Identify a block `B` on an adversarial fork that is in the node's VolatileDB (slot ≥ immutable tip slot).
3. Construct a `PerasCert` with `pcCertRound = <any round not yet in the DB>` and `pcCertBoostedBlock = blockPoint B`.
4. Send the certificate via the object-diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
6. The certificate is stored in `PerasCertDB`; `ChainDB.addPerasCertAsync` is called.
7. `chainSelSync` triggers `chainSelectionForBlock` for `B`; the `PerasWeightSnapshot` now assigns weight 15 to `B`.
8. `compareAnchoredFragments` computes the total weight of the adversarial fork as `blockNo(tip) + 15`; if this exceeds the honest chain's weight, the node switches forks. [7](#0-6) [8](#0-7) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L143-149)
```haskell
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
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
