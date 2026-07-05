### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate, performing no cryptographic or structural validation. Any certificate received from an unprivileged peer via the Peras object-diffusion mini-protocol is accepted and stored, and can then trigger chain selection to boost an arbitrary block — the direct analog of the external report's missing `isSupported` check before processing a deposit asset.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve a `PerasCert` before it is stored and acted upon. The default instance, which applies to all block types including `CardanoBlock`, is a placeholder that always succeeds:

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

The inbound certificate processing pipeline in `processCerts` calls this stub directly, passing the hardcoded `mkPerasParams` placeholder instead of the actual node configuration:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` filters only for duplicate round numbers, then passes every non-duplicate certificate through `validateCert`. Because `validateCert` is the stub above, every certificate passes and is forwarded to `addCert`: [4](#0-3) 

The accepted certificate is then handed to `ChainDB.addPerasCertAsync`, which feeds `chainSelSync`. That function reads the boosted block from `VolatileDB` and calls `chainSelectionForBlock` for it, potentially causing the node to switch to a chain it would otherwise not prefer: [5](#0-4) 

The same stub is used for the vote-pool writer path: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

A malicious peer that can speak the Peras object-diffusion mini-protocol can craft a `PerasCert` that claims to boost any block hash and round number. Because `validatePerasCert` never rejects anything, the certificate is stored and `chainSelSync` triggers `chainSelectionForBlock` for the attacker-chosen block. If that block is present in the node's `VolatileDB`, the node may switch to a chain it would not otherwise select, violating chain-selection safety. This maps to:

> **High. Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

and also:

> **Critical. Bypass of Peras certificate checks that enables unauthorized certificate acceptance.**

---

### Likelihood Explanation

The Peras object-diffusion infrastructure is wired into the production `ChainDB` and networking stack. The `makePerasCertPoolWriterFromChainDB` function is the production entry point and it uses the stub validator. Any peer that negotiates the Peras mini-protocol version can send arbitrary certificates. No privileged access, key material, or stake majority is required — only the ability to connect to the node and send a well-formed CBOR-encoded `PerasCert`.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's BLS aggregate signature over the claimed round number and boosted block hash.
2. That the signers are legitimate committee members for the claimed round (committee eligibility check).
3. That the quorum threshold is met by the aggregate stake of the signers.

Until real validation is implemented, the Peras object-diffusion mini-protocol should not be negotiated or enabled in production builds, so that `processCerts` / `chainSelSync` cannot be reached by an unprivileged peer.

---

### Proof of Concept

1. Connect to a target node that has the Peras object-diffusion mini-protocol enabled.
2. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block hash known to be in the node's `VolatileDB` (obtainable via ChainSync).
3. Send the certificate via the object-diffusion protocol. `processCerts` will call `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{...}` unconditionally.
4. The certificate is stored and `ChainDB.addPerasCertAsync` is called.
5. `chainSelSync` reads the boosted block from `VolatileDB` and calls `chainSelectionForBlock`, potentially causing the node to switch to the attacker-chosen chain fragment. [8](#0-7) [1](#0-0)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-111)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```
