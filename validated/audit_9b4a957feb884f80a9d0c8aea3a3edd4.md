### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or semantic checks. This stub is wired directly into the production Peras certificate inbound pipeline (`processCerts` in `PerasCert.hs`), which is reachable by any unprivileged peer via the ObjectDiffusion mini-protocol. A malicious peer can therefore inject a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block in the node's VolatileDB, causing the node to treat that block as boosted and trigger chain selection for it, potentially preferring a non-canonical chain.

---

### Finding Description

**Root cause — stub validation that always succeeds:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve a certificate before it enters the node's state. The universal instance (which covers all block types in production) implements this gate as:

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

No field of `cert` is inspected. The function ignores `pcCertRound`, `pcCertBoostedBlock`, any aggregate BLS signature, and any committee membership proof. Every certificate, regardless of content or origin, is wrapped in `ValidatedPerasCert` and returned as valid.

**Production wiring — stub used for all inbound peer certificates:**

Both production pool-writer constructors pass this stub directly as the `validateCert` argument to `processCerts`:

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

`processCerts` calls `validateCert` on each peer-supplied certificate and, if all pass (which they always do), adds them to the ChainDB: [3](#0-2) 

**Chain selection trigger — accepted certificate causes block boost:**

Once a certificate is added to the ChainDB via `addPerasCertAsync`, `chainSelSync` processes it. It reads `pcCertBoostedBlock` from the certificate, looks up that block in the VolatileDB, and triggers `chainSelectionForBlock` for it:

```haskell
boostedHdr <-
  lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
    Nothing -> ...
    Just boostedHdr -> pure boostedHdr
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `ValidatedPerasCert` carries a `vpcCertBoost` weight (set to `perasWeight mkPerasParams = PerasWeight 15`) that is added to the chain weight during selection. A block that would otherwise lose chain selection can win if it is boosted by a certificate — even a fake one.

**Analog to the original report:**

The original report describes `claimReceipts(market, receipt)` where `market` is never checked against `receipt.tracer`, allowing a malicious caller to mix a legitimate receipt with a wrong market context. Here, `validatePerasCert params cert` never checks any field of `cert` against `params` or against the chain state — the certificate's claimed round number, boosted block, and aggregate signature are all ignored. The `cert` object's own fields are never cross-validated against the context in which it is being accepted.

---

### Impact Explanation

**Impact: High** — Chain selection manipulation by an unprivileged peer.

A malicious peer can send a `PerasCert` with `pcCertBoostedBlock` set to the point of any block currently in the target node's VolatileDB. The node will:
1. Accept the certificate unconditionally (no signature check, no committee check, no round-number check).
2. Store it in the `PerasCertDB`.
3. Trigger chain selection for the boosted block, adding `PerasWeight 15` to its chain weight.

If the adversary's target block is on a fork that would otherwise lose chain selection, the artificial boost can flip the outcome, causing the honest node to switch to a non-canonical chain. This directly violates the Peras security assumption that only a legitimate quorum of committee members can boost a block.

This falls under: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Likelihood: High.**

- The ObjectDiffusion mini-protocol for Peras certificates is a standard peer-to-peer protocol reachable by any node that connects to the target.
- No privileged access, no key material, and no stake is required. The attacker only needs to craft a `PerasCert` CBOR message with a desired `pcCertRound` and `pcCertBoostedBlock`.
- The `PerasCert` serialization format is public and straightforward (a 2-element CBOR list of round number and block point): [5](#0-4) 

- The attacker needs to know a block hash present in the target's VolatileDB, which is obtainable via the ChainSync protocol.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that performs all required checks before a certificate is accepted:

1. **Aggregate signature verification**: Verify the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set.
2. **Committee membership and quorum**: Verify that the signers were eligible committee members for `pcCertRound` and that their combined stake meets the quorum threshold (`perasQuorumStakeThreshold`).
3. **Round number bounds**: Verify that `pcCertRound` is within the valid acceptance window relative to the current chain tip (not expired, not from the future).
4. **Boosted block existence and ancestry**: Verify that `pcCertBoostedBlock` is a known block on a chain that extends from the node's immutable tip.

Until the full implementation is in place, the stub should reject all certificates (`Left PerasValidationErr`) rather than accept all of them, to prevent the attack surface from being live in production.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target Cardano node running the Peras-enabled consensus code.
2. Attacker initiates the ObjectDiffusion mini-protocol for Peras certificates (the `PerasCertDiffusion` protocol).
3. Attacker learns a block hash `H` of a block on a competing fork in the target's VolatileDB (obtainable via ChainSync).
4. Attacker crafts a `PerasCert` CBOR payload:
   - `pcCertRound = <any valid round number>`
   - `pcCertBoostedBlock = BlockPoint <slot> H`
5. Attacker sends this certificate to the target node via the ObjectDiffusion inbound handler.

**Node processing:**

- `processCerts` is called with the crafted certificate.
- `validatePerasCert mkPerasParams cert` is called → returns `Right (ValidatedPerasCert cert (PerasWeight 15))` unconditionally.
- The certificate passes the `partitionEithers` check (no errors).
- `ChainDB.addPerasCertAsync chainDB` is called with the validated certificate.
- `chainSelSync` processes the certificate, looks up block `H` in the VolatileDB, and calls `chainSelectionForBlock` with `PerasWeight 15` added to `H`'s chain weight.

**Expected outcome:** The target node may switch its selected chain to the fork containing block `H`, even though no legitimate quorum of Peras committee members ever voted for it. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-137)
```haskell
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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
