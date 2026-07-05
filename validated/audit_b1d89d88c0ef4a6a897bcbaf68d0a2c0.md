### Title
Stub `validatePerasCert` Unconditionally Accepts All Peer-Supplied Peras Certificates, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Because the Peras certificate diffusion pipeline (`processCerts`) calls this function to gate admission into the `PerasCertDB` and subsequently into chain selection, any unprivileged peer can inject an arbitrary `PerasCert` — pointing to any block on any fork — and cause the receiving node to assign artificial weight boost to that fork, potentially triggering a chain switch away from the honest chain.

---

### Finding Description

**Root cause — stub validation always succeeds:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for accepting inbound certificates. The universal instance (the only production instance) implements it as:

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

No signature verification, no committee membership check, no round-number bounds check, no boosted-block existence check — the function returns `Right` for every input unconditionally. [1](#0-0) 

The `PerasCertDB.Impl` layer carries the same acknowledgement: `"TODO: we will need to update this method with non-trivial validation logic"`. [2](#0-1) 

**Attacker-controlled entry path — ObjectDiffusion inbound pipeline:**

Inbound Peras certificates from peers are processed by `processCerts` in the ObjectDiffusion pool writer. It calls `validatePerasCert mkPerasParams` on each certificate not already in the DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validateCert = validatePerasCert mkPerasParams` always returns `Right`, the `([], validatedCerts)` branch is always taken and every peer-supplied certificate is admitted. [3](#0-2) [4](#0-3) 

The production path via `makePerasCertPoolWriterFromChainDB` uses the same stub: [5](#0-4) 

**Chain selection impact — admitted cert triggers fork switch:**

Once admitted, the certificate is stored in `PerasCertDB` and its boost is reflected in the `PerasWeightSnapshot`. `chainSelSync` then calls `chainSelectionForBlock` for the boosted block, which re-evaluates whether the fork containing that block is now preferred over the current chain:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

Chain selection uses `WeightedSelectView` / `wsvTotalWeight` which sums `wsvBlockNo + wsvWeightBoost`. An attacker-injected certificate adds `perasWeight` (a configurable `Word64`) to the total weight of any fork, potentially making it preferred over the honest chain. [7](#0-6) 

---

### Impact Explanation

**Impact: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

A malicious peer connected via the Peras certificate ObjectDiffusion mini-protocol can craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block on a minority fork. Because `validatePerasCert` performs no checks, the certificate is admitted and its boost is applied. If `perasWeight` is large enough relative to the block-number difference between the honest chain and the fork, the node will switch to the adversarial fork. This constitutes a chain selection integrity failure: the node abandons the honest chain in favor of a non-canonical chain based on a fabricated, cryptographically unverified certificate.

---

### Likelihood Explanation

**Likelihood: Medium** — Peras is not enabled by default on mainnet (the CHANGELOG notes "if Peras is disabled (which is the default), there is no observable difference"). However, the vulnerability is fully reachable on any private testnet or staging environment where Peras is enabled, which is the intended deployment target for this feature. Any peer that can establish an ObjectDiffusion connection can exploit this with zero cryptographic capability — no keys, no stake, no special privileges required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before Peras is enabled in any networked environment. At minimum, the validation must verify:

1. The certificate's aggregate BLS signature against the claimed committee members' public keys.
2. That the claimed voters are legitimate committee members for the stated round (using the epoch nonce and stake distribution).
3. That the boosted block's slot falls within the valid range for the certificate's round number.
4. That the total voting weight of the signers meets the quorum threshold.

Until real validation is implemented, the Peras certificate diffusion pipeline must not be activated on any node that participates in a network with untrusted peers.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node as a peer via the Peras certificate ObjectDiffusion protocol.
2. Craft a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <tip of a minority fork>`.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..}` unconditionally.
4. The certificate is stored in `PerasCertDB`. `chainSelSync` calls `chainSelectionForBlock` for the boosted block.
5. `weightBoostOfFragment` adds `perasWeight` to the fork's total weight. If `perasWeight > (honest_tip_blockno - fork_tip_blockno)`, the node switches to the adversarial fork.

The stub is at `SupportsPeras.hs:353–358`; the admission gate is at `PerasCert.hs:164–173`; the chain selection trigger is at `ChainSel.hs:529–532`. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-105)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L124-127)
```haskell
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L41-60)
```haskell
data WeightedSelectView proto = WeightedSelectView
  { wsvBlockNo :: !BlockNo
  -- ^ The 'BlockNo' at the tip of a fragment.
  , wsvWeightBoost :: !PerasWeight
  -- ^ The weight boost of a fragment (w.r.t. a particular anchor).
  , wsvTiebreaker :: TiebreakerView proto
  -- ^ Lazy because it is only needed when 'wsvTotalWeight' is inconclusive.
  }

deriving stock instance Show (TiebreakerView proto) => Show (WeightedSelectView proto)
deriving stock instance Eq (TiebreakerView proto) => Eq (WeightedSelectView proto)

-- TODO: More type safety to prevent people from accidentally comparing
-- 'WeightedSelectView's obtained from fragments with different anchors?
-- Something ST-trick like?

-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
```
