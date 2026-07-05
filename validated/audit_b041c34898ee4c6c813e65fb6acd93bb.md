### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Weight Inflation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. Any unprivileged peer can therefore inject arbitrary Peras certificates over the ObjectDiffusion mini-protocol. Each accepted certificate is stored in the `PerasCertDB` and its boost weight is applied to chain selection, allowing an attacker to artificially inflate the weight of any block they choose and cause an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must approve a certificate before it is stored. The sole production instance (the universal `StandardHash blk` instance) implements this gate as a stub:

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

This stub is wired directly into the production inbound path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls this validator on every inbound certificate and, if it returns `Right` (which it always does), immediately stores the certificate:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [3](#0-2) 

The `PerasCertDB.implAddCert` implementation also carries a matching TODO confirming that non-trivial validation is absent:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [4](#0-3) 

Once stored, `chainSelSync` for `ChainSelAddPerasCert` unconditionally adds the certificate to the `PerasCertDB` and updates the `PerasWeightSnapshot`: [5](#0-4) 

Chain selection then uses `weightedSelectView` / `wsvTotalWeight` to compare candidate chains, where the total weight is `blockNo + weightBoost`. A certificate with a large `vpcCertBoost` (set to `perasWeight mkPerasParams` for every accepted cert) can push a minority-fork candidate above the canonical chain's total weight: [6](#0-5) 

The analog to the external report is exact: just as `deposit()` updates `_balances[asset][msg.sender]` without checking that `asset` has code, `processCerts` updates the `PerasCertDB` weight snapshot without checking that the certificate carries a valid aggregate signature, a legitimate committee membership proof, or any other credential.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` referencing any `pcCertBoostedBlock` with an arbitrarily large boost. Because `validatePerasCert` always returns `Right`, the certificate is stored and its boost is applied to chain selection. If the boosted block is on a fork (or arrives later), the node will switch to that fork once the block is received, even if the fork is shorter or less secure than the canonical chain. This constitutes a chain-selection manipulation: an honest node is made to prefer a non-canonical chain solely on the basis of a fabricated certificate, violating the Peras security assumption that only legitimately quorum-certified blocks receive weight boosts.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is reachable by any peer that connects to the node. No stake, key material, or privileged access is required. The attacker only needs to craft a `PerasCert` CBOR message with a desired `pcCertRound` and `pcCertBoostedBlock` and send it over the wire. The stub validation provides zero resistance.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS signature over `(roundNo, boostedBlock)` against the claimed committee members' public keys.
2. That each claimed voter's eligibility proof is valid for the given round.
3. That the total stake of the signers meets the quorum threshold.

Until the full BLS/committee infrastructure is in place, the inbound ObjectDiffusion handler for certificates should be disabled or gated behind a feature flag so that no peer-supplied certificate can reach `processCerts` in production.

---

### Proof of Concept

```
-- Attacker connects to a node running the ObjectDiffusion cert protocol.
-- Craft a certificate boosting a block on a minority fork:
let craftedCert = PerasCert
      { pcCertRound      = PerasRoundNo 999
      , pcCertBoostedBlock = BlockPoint (SlotNo 100) minorityForkHash
      }
-- Send it via the ObjectDiffusion inbound protocol.
-- processCerts calls (validatePerasCert mkPerasParams craftedCert)
-- which unconditionally returns:
--   Right (ValidatedPerasCert { vpcCert = craftedCert
--                              , vpcCertBoost = perasWeight mkPerasParams })
-- The certificate is stored in PerasCertDB.
-- PerasWeightSnapshot now contains (BlockPoint 100 minorityForkHash, perasWeight mkPerasParams).
-- When the minority-fork block arrives, chainSelectionForBlock computes:
--   wsvTotalWeight candidate = blockNo + perasWeight mkPerasParams
-- which exceeds the canonical chain's total weight, causing a fork switch.
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
