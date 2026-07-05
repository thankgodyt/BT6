### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts All Inbound Certificates — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate catch-all `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or structural checks. This instance is wired directly into the production inbound-certificate processing path via `makePerasCertPoolWriterFromChainDB`. Any unprivileged peer can inject a crafted certificate that is silently accepted, granting an arbitrary block a Peras weight boost and potentially causing honest nodes to prefer a non-canonical chain.

---

### Finding Description

**Root cause — wrong "variable" in the validation check**

The external report's pattern is: a validation function captures the wrong metric (local balance instead of total supply), so the guard always evaluates to "pass". The analog here is structurally identical: `validatePerasCert` captures *no* metric from the certificate at all — it ignores the certificate content entirely and always returns `Right`.

`BlockSupportsPeras.hs` lines 350–358:

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

The function discards `cert` entirely. No BLS aggregate-signature check, no voter-eligibility proof check, no round-number range check, no boosted-block existence check is performed. Every certificate, valid or forged, is wrapped in `Right` and returned as a `ValidatedPerasCert`.

**Production code path**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` (line 126) passes this function directly as the validator for all inbound peer certificates:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
```

The comment confirms this is the live code path, not a test stub. `processCerts` (lines 164–173 of `PerasCert.hs`) then calls `validateCert` on every certificate received from a peer:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertInboundException errs)
```

Because `validatePerasCert` never produces a `Left`, the `(errs, _)` branch is unreachable. Every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`, which stores it in the `PerasCertDB` and triggers `chainSelSync` → `chainSelectionForBlock` for the boosted block.

**End-to-end exploit path**

1. Peer sends a crafted `PerasCert blk { pcCertRound = r, pcCertBoostedBlock = adversarialPoint }`.
2. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
3. Certificate is stored; `chainSelSync` triggers chain selection for `adversarialPoint`.
4. `weightedSelectView` / `preferAnchoredCandidate` now sees the fake weight boost on the adversarial block.
5. If the boosted block is on a fork, the node may switch to that fork.

---

### Impact Explanation

This is a **Critical** bypass of Peras certificate/vote checks. An unprivileged peer can make any honest node accept a forged certificate, granting an arbitrary block a `perasWeight`-sized boost. Because Peras weight is additive to block-number in chain selection (`totalWeightOfFragment`), a sufficiently boosted adversarial fork can be preferred over the honest chain, causing the node to adopt a non-canonical or adversarially controlled chain. This directly violates the "bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance" criterion.

---

### Likelihood Explanation

The attack requires only a network connection to the target node. The inbound certificate diffusion path (`makePerasCertPoolWriterFromChainDB` → `processCerts`) is reachable by any peer. No stake, no keys, and no prior knowledge of the chain state are required — the attacker only needs to know a block point they wish to boost.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:
1. Verifies the aggregate BLS signature over `(roundNo, boostedBlock)` against the declared voter set.
2. Verifies each voter's eligibility proof (persistent seat or VRF non-persistent proof).
3. Checks that the total stake of the declared voters meets the quorum threshold.
4. Validates that the round number is within the acceptable window.

Until the full plumbing is in place, the function should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the fail-safe direction is safe.

---

### Proof of Concept

```
Attacker peer  →  sends PerasCert { pcCertRound = 999, pcCertBoostedBlock = adversarialForkTip }
                                                                                    ↓
makePerasCertPoolWriterFromChainDB / processCerts
  validatePerasCert mkPerasParams cert
    → Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }
                                                                                    ↓
ChainDB.addPerasCertAsync  →  PerasCertDB stores cert
                                                                                    ↓
chainSelSync (ChainSelAddPerasCert)
  chainSelectionForBlock cdb BlockCache.empty adversarialForkHeader noPunishment
                                                                                    ↓
preferAnchoredCandidate sees adversarialFork weight = blockNo + perasWeight
  → ShouldSwitch  →  node adopts adversarial fork
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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
