### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Force Chain Switch via Fake Boost - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or structural checks. Because the `PerasCert` associated data type in this instance carries no signature field at all, any peer can craft a certificate that boosts an arbitrary fork block. The certificate is accepted by the production `hPerasCertDiffusionClient` miniprotocol handler, stored in the `PerasCertDB`, and immediately triggers chain selection for the boosted block. If the boosted block is on a fork that is now heavier than the current chain under the Peras weighted comparison, the node switches to that fork — exactly mirroring the AuctionCrowdfund pattern where an attacker manipulates external state to bypass a "don't switch" guard and force a worse outcome.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The degenerate catch-all instance for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  data PerasCert blk = PerasCert
    { pcCertRound        :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }   -- ← no signature field whatsoever

  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right ValidatedPerasCert
      { vpcCert      = cert
      , vpcCertBoost = perasWeight params
      }   -- ← always succeeds, no checks performed
``` [1](#0-0) 

**Production miniprotocol wires this directly into the inbound cert handler:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the sole validation gate for every certificate received from a peer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    }
``` [2](#0-1) 

This writer is registered as the live `hPerasCertDiffusionClient` handler in the node-to-node stack:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

**Chain selection is triggered unconditionally after acceptance:**

`chainSelSync` for `ChainSelAddPerasCert` adds the certificate to the `PerasCertDB` and, if the boosted block is not on the current chain, calls `chainSelectionForBlock` for that block:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $
    idExitEarly addedCertRes          -- only exits early if block is already on OUR chain
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Weighted chain selection uses the injected boost:**

`preferAnchoredCandidate` computes `wsvTotalWeight = blockNo + weightBoost`. A fake certificate adds `perasWeight params` to the fork's weight, potentially making it exceed the current chain's weight and triggering a switch. [5](#0-4) 

---

### Impact Explanation

**Impact: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

When Peras is enabled, any peer can send a `PerasCert` message naming an arbitrary fork block. Because `validatePerasCert` always returns `Right`, the certificate is stored and its boost is added to the `PerasWeightSnapshot`. If the boost is large enough to make the fork's `wsvTotalWeight` exceed the current chain's, `chainSelectionForBlock` switches the node to the attacker's fork. The attacker needs no stake, no keys, and no knowledge of the committee — only the hash of a block already in the victim's `VolatileDB`.

This directly mirrors the AuctionCrowdfund M-07 pattern: the "don't switch" guard (`preferAnchoredCandidate` returning `ShouldNotSwitch`) is bypassed by injecting external state (a fake certificate) that inflates the candidate's apparent weight, forcing the node to take a worse action (chain switch) it would otherwise refuse.

---

### Likelihood Explanation

**Likelihood: Medium** (conditional on Peras being enabled; trivial to exploit once enabled).

Peras is disabled by default per the CHANGELOG ("Note that if Peras is disabled (which is the default), there is no observable difference"). However, the miniprotocol handler is fully wired into the production node-to-node stack and the TODO comments explicitly acknowledge that real validation is not yet implemented (issues #73 and #120). Once Peras is enabled — which is the stated roadmap goal — any connected peer can execute this attack with a single crafted message, requiring no cryptographic material whatsoever.

---

### Recommendation

1. **Do not enable Peras in production until `validatePerasCert` performs full cryptographic validation** (aggregate BLS signature verification against the committee's public keys, round-number range checks, boosted-block eligibility checks). The V1 certificate type in `Peras/Cert/V1.hs` already carries `pcSignature :: AggregateVoteSignature PerasBLSCrypto` and `pcVoters :: PerasCertVoters`; a concrete `BlockSupportsPeras` instance for Cardano blocks must use these fields.

2. **Remove or gate the catch-all `instance StandardHash blk => BlockSupportsPeras blk`** so that enabling Peras for a block type without a proper instance is a compile-time error rather than a silent no-op validation.

3. **Add a feature-flag guard** in `makePerasCertPoolWriterFromChainDB` that rejects all inbound certificates when Peras is not yet fully validated, preventing the miniprotocol from being exploitable even if the flag is accidentally set.

---

### Proof of Concept

**Setup:** Peras enabled on a private testnet. Honest node H has current chain `C` (tip block `B_c`, `blockNo = N`). Attacker A has a fork block `B_f` (already diffused to H's `VolatileDB`, `blockNo = N-1`) whose chain would normally lose chain selection.

**Steps:**

1. A connects to H via the node-to-node `hPerasCertDiffusionClient` miniprotocol.
2. A sends a single `PerasCert` message: `{ pcCertRound = R, pcCertBoostedBlock = point(B_f) }`.
3. H's `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
4. H calls `ChainDB.addPerasCertAsync` → queues `ChainSelAddPerasCert`.
5. `chainSelSync` finds `B_f` is not on the current chain, calls `chainSelectionForBlock` for `B_f`.
6. `constructPreferableCandidates` computes `weightedSelectView` for the fork: `wsvTotalWeight = (N-1) + perasWeight`. If `perasWeight > 1`, this exceeds `N` (the current chain's weight), so `preferAnchoredCandidate` returns `ShouldSwitch`.
7. H switches to A's fork, rolling back one block.

No stake, no keys, no prior chain knowledge beyond `point(B_f)` is required.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
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
