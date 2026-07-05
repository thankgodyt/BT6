### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that unconditionally returns `Right` — accepting every certificate without performing any cryptographic or semantic check. This function is wired directly into the production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`). When Peras is enabled, any unprivileged peer can inject arbitrarily crafted certificates that boost any block, artificially inflating its chain-selection weight and potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — always-`Right` validation:** [1](#0-0) 

The comment explicitly marks this as a degenerate placeholder (`-- TODO: degenerate instance for all blks to get things to compile`), yet the instance is `instance StandardHash blk => BlockSupportsPeras blk` — a universal instance that covers every block type, including `CardanoBlock`. No more-specific instance overrides it. The body of `validatePerasCert` is:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No signature check, no round-number check, no boosted-block existence check — the certificate is stamped valid unconditionally.

**Production call site — inbound peer pipeline:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`. The `processCerts` function partitions results with `partitionEithers (validateCert <$> certsNotAlreadyInDb)`: because `validateCert` always returns `Right`, the left (error) list is always empty and every certificate is unconditionally added to the `PerasCertDB`. [3](#0-2) 

**Chain-selection impact:**

Once a certificate is in the `PerasCertDB`, `chainSelSync` is triggered for the boosted block: [4](#0-3) 

Chain selection uses `weightedSelectView` / `preferAnchoredCandidate`, which sums `wsvBlockNo` and `wsvWeightBoost` (the Peras boost) to compute total weight: [5](#0-4) 

A fake certificate with a large `perasWeight` can make a shorter, non-canonical candidate fragment outweigh the honest chain, causing the node to switch.

---

### Impact Explanation

**Impact class: High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

When Peras is enabled, a single peer can:
1. Craft a `PerasCert` pointing to any block hash and any round number.
2. Deliver it via the Peras object-diffusion mini-protocol.
3. The certificate passes `validatePerasCert` unconditionally.
4. The boosted block's weight is inflated in the `PerasWeightSnapshot`.
5. Chain selection may switch the node to a non-canonical fork, breaking consensus safety.

The analog to the external report is exact: just as `TAKER_VAULT_ID = 80085` is a hardcoded placeholder substituted for the real per-user `assetId`, `validatePerasCert` substitutes a hardcoded "always valid" judgment for the real per-certificate cryptographic check, causing the system to operate on the wrong (attacker-controlled) identity.

---

### Likelihood Explanation

Peras is not enabled by default (CHANGELOG: *"Note that if Peras is disabled (which is the default), there is no observable difference"*), so the attack surface is currently limited to nodes that opt in. However:
- The code is in the production library, not behind a compile-time flag.
- The object-diffusion mini-protocol for certificates is wired up whenever Peras is enabled.
- No stake, key material, or operator access is required — any peer connection suffices.

Likelihood is **medium**: low on mainnet today, but high on any Peras-enabled testnet or future mainnet deployment.

---

### Recommendation

1. **Implement real validation** in `validatePerasCert`: verify the aggregate BLS signature over `(roundNo, boostedBlock)` using the committee's public keys, check that `pcCertRound` is within the expected window, and confirm `pcBoostedBlock` refers to a known block.
2. **Remove or gate the degenerate instance** behind a compile-time flag so it cannot be accidentally used in production.
3. **Track the open issue** (`https://github.com/tweag/cardano-peras/issues/120`) and block Peras enablement on mainnet until validation is complete.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <fork tip> }
  │  via Peras object-diffusion mini-protocol
  ▼
makePerasCertPoolWriterFromChainDB
  └─ processCerts ... (validatePerasCert mkPerasParams) ...
       └─ validatePerasCert _ cert = Right (ValidatedPerasCert cert boost)
            ──► certificate accepted, added to PerasCertDB
                  └─ chainSelSync triggers chain selection for <fork tip>
                       └─ weightedSelectView: fork weight = blockNo + boost
                            ──► if boost > (honest chain length - fork length),
                                node switches to attacker's fork
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-88)
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
