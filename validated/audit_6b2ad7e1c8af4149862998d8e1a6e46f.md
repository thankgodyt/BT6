### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Selection Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing no cryptographic or structural checks. Because this function gates the entire Peras certificate ingest pipeline — including the `ChainDB` path that triggers chain selection — any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary block in the VolatileDB, causing an honest node to switch to a chain it would otherwise reject.

---

### Finding Description

The `BlockSupportsPeras` type-class defines `validatePerasCert` as the mandatory gate before a certificate is accepted into the node. The sole production instance (the universal `StandardHash blk` instance that covers all Cardano block types) implements this gate as:

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

This stub is wired directly into the **production** object-diffusion ingest path via `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, because the stub always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Inside `chainSelSync`, the accepted certificate triggers `chainSelectionForBlock` for the boosted block, applying the full Peras weight boost to that block's chain: [4](#0-3) 

The `validatePerasVote` implementation has the same structural problem — it checks only whether the claimed voter ID exists in the stake distribution, but performs **no cryptographic signature verification**, meaning any peer can forge votes for any stakepool: [5](#0-4) 

---

### Impact Explanation

**Vulnerability class:** Bypass of Peras certificate/vote verification that enables unauthorized certificate acceptance and chain-selection manipulation.

An unprivileged peer can:

1. Craft a `PerasCert` naming any block hash present in the target node's VolatileDB as `pcCertBoostedBlock`.
2. Send it via the Peras object-diffusion mini-protocol.
3. `validatePerasCert` returns `Right` unconditionally; the certificate is stored in `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
4. `chainSelSync` runs `chainSelectionForBlock` for the boosted block, applying the full `perasWeight` boost.
5. The node's chain-selection logic now treats the attacker-chosen block as having Peras-certified weight, potentially switching the node's selection to a chain it would otherwise not prefer.

Because Peras weight is the mechanism by which the protocol achieves fast finality and resists adversarial forks, accepting forged certificates directly undermines the chain-selection security guarantee. A node that switches to an attacker-boosted chain may diverge from the honest majority, constituting a consensus safety failure reachable by any peer without any key material.

This maps exactly to the external report's class: a critical validation gate (certificate authenticity) is absent, allowing an attacker to inject state (a boosted block) that manipulates a downstream critical action (chain selection), analogous to the missing graduation check that allowed manipulation of liquidity pool reserves.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is reachable from any connected peer without authentication. The stub is the **only** registered instance of `validatePerasCert` for all Cardano block types (the `StandardHash blk` universal instance). No operator configuration or key compromise is required. The attack requires only the ability to send a well-formed CBOR-encoded `PerasCert` message naming a known block hash, which is publicly observable from the ChainSync protocol.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real check before the certificate is forwarded to `ChainDB.addPerasCertAsync`. At minimum, the implementation must verify:

1. **Committee membership** — the certificate's claimed signers are legitimate members of the Peras voting committee for the stated round.
2. **Cryptographic signatures** — each signer's BLS/KES signature over `(roundNo, boostedBlock)` is valid.
3. **Quorum** — the aggregate stake of valid signers meets the `perasQuorumStakeThreshold`.
4. **Round validity** — the round number is within the acceptable window relative to the current chain tip.

The same applies to `validatePerasVote`: stake-distribution lookup is not a substitute for signature verification.

Until real validation is in place, the Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`) should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.

---

### Proof of Concept

On a private testnet node with Peras enabled:

```
# 1. Observe a block hash H in the peer's VolatileDB via ChainSync.
# 2. Craft a minimal CBOR PerasCert:
#      [ roundNo :: Word64, boostedBlock :: (slotNo, H) ]
# 3. Send it via the Peras object-diffusion mini-protocol.
# 4. validatePerasCert returns Right unconditionally (SupportsPeras.hs:353-358).
# 5. processCerts adds it via ChainDB.addPerasCertAsync (PerasCert.hs:132).
# 6. chainSelSync triggers chainSelectionForBlock for H with full perasWeight
#    (ChainSel.hs:529-531).
# 7. Observe the node's selection switch to the attacker-chosen chain.
```

The `PerasCert` wire format is defined at: [6](#0-5) 

No key material, stake, or operator access is required. The attack is repeatable for any round number not already present in the `PerasCertDB`.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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
