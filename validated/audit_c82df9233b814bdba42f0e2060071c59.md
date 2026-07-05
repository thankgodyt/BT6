### Title
Peras Certificate Validation Bypass: Stub `validatePerasCert` Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance provides a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing no cryptographic or committee-membership checks. This stub is wired directly into the production Peras certificate diffusion path. When Peras is enabled, any unprivileged peer can send a crafted `PerasCert` for an arbitrary block, bypass all validation, and cause the receiving node to apply a weight boost to a non-canonical chain fragment, potentially triggering a fork switch away from the honest chain.

---

### Finding Description

**Analog mapping.** The external report describes a Governor contract that holds admin rights over Timelock but never exposes `cancelTransaction`, making the capability permanently unreachable. The analog here is structurally identical: the `BlockSupportsPeras` typeclass declares `validatePerasCert` as the hook for certificate validation (the "capability"), but the universal instance that is wired into production never exercises that capability — it always returns `Right` regardless of certificate content.

**Root cause — stub validator.**

The `BlockSupportsPeras` typeclass declares:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance (the only instance in the codebase, used for all block types) implements it as:

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

This always returns `Right`, unconditionally wrapping the caller-supplied certificate as `ValidatedPerasCert`. No signature is checked, no committee membership is verified, no round-number bounds are enforced. [1](#0-0) 

**Production wiring — certificate diffusion path.**

`makePerasCertPoolWriterFromChainDB` is the production entry point for certificates received from peers over the Peras object-diffusion mini-protocol. It passes the stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls this validator on every inbound certificate. Because it always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection consequence.**

`chainSelSync` processes the accepted certificate: it inserts it into `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then uses `preferAnchoredCandidate`, which computes `wsvTotalWeight = BlockNo + weightBoost`. With the default `perasWeight = PerasWeight 15` from `mkPerasParams`, a fork **15 blocks shorter** than the current selection can be preferred if it carries a certificate boost: [5](#0-4) [6](#0-5) 

**The "missing capability" parallel.** The typeclass interface declares the validation capability (`validatePerasCert`), just as the Governor contract holds admin rights over Timelock. But the only concrete implementation never exercises that capability — it always returns `Right` — just as the Governor never calls `cancelTransaction`. The result is that the committed state (an accepted certificate and its chain-weight boost) can never be rejected, mirroring the Timelock scenario where a queued transaction can never be canceled.

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert{pcCertRound = r, pcCertBoostedBlock = p}` targeting any block point `p` on any fork.
2. Send it via the Peras certificate diffusion mini-protocol.
3. The receiving node calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally — no cryptographic check, no committee-membership check, no round-validity check.
4. The certificate is stored in `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block.
5. Any candidate chain containing `p` now carries an extra weight of 15, sufficient to displace the honest chain if the fork is up to 15 blocks shorter.

This is a **bypass of Peras certificate/vote verification** that enables unauthorized certificate acceptance and chain selection manipulation — a non-canonical chain can be made to appear heavier than the honest chain to an honest node.

---

### Likelihood Explanation

The attack requires only a network connection to the target node and the ability to send a well-formed `PerasCert` message. No keys, no stake, no special privileges are needed. The code path from peer message receipt → `processCerts` → `validatePerasCert` → `addPerasCertAsync` → `chainSelSync` is direct and fully reachable. The condition is that Peras must be enabled on the target node; the CHANGELOG confirms Peras is disabled by default but is an explicit feature flag, and the production diffusion code is already wired and compiled in.

---

### Recommendation

1. **Short term:** Implement actual cryptographic and committee-membership validation inside `validatePerasCert` before enabling Peras on any network. Until real validation is in place, the stub should reject all externally received certificates (only locally-forged certificates should be accepted). The referenced issue https://github.com/tweag/cardano-peras/issues/120 must be resolved before Peras is enabled.

2. **Long term:** The `BlockSupportsPeras` typeclass should not provide a universal catch-all instance that silently accepts everything. Each concrete block type that supports Peras should provide its own instance with real validation logic, preventing the "degenerate instance for all blks to get things to compile" pattern from ever reaching a production deployment.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect as a peer to an honest node.
2. Identify a shorter fork candidate chain `F` (up to 15 blocks shorter than the honest tip).
3. Craft `cert = PerasCert { pcCertRound = <any valid round>, pcCertBoostedBlock = <tip of F> }`.
4. Send `cert` via the Peras certificate diffusion mini-protocol.
5. The node executes `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}`.
6. `chainSelSync` adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
7. `preferAnchoredCandidate` computes `wsvTotalWeight(F) = blockNo(F) + 15 > wsvTotalWeight(honest)` if `F` is within 15 blocks of the honest tip.
8. The node switches to fork `F`, diverging from the honest chain. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
