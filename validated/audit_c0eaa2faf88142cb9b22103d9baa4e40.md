### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Forge Peras Certificate Boosts and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound `PerasCert`, regardless of content. Because this function is wired directly into the network-facing Peras certificate object-diffusion writer (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can send a crafted certificate that boosts an arbitrary block. The boosted block then receives a `PerasWeight 15` bonus in chain selection, which can cause an honest node to prefer a non-canonical chain over the honest chain.

---

### Finding Description

**Root cause — missing validation gate:**

`validatePerasCert` in the degenerate `BlockSupportsPeras` instance accepts every certificate unconditionally:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params   -- always PerasWeight 15
        }
``` [1](#0-0) 

**Entry point — network-facing writer:**

`makePerasCertPoolWriterFromChainDB` is the production writer used when Peras is enabled. It passes the stub directly as the certificate validator:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` applies this validator to every certificate received from a peer. Because the stub never returns `Left`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection side-effect:**

`chainSelSync` processes each accepted certificate. It reads the `pcCertBoostedBlock` field directly from the attacker-supplied cert and, if the boosted block is in the VolatileDB, immediately triggers `chainSelectionForBlock` for it: [4](#0-3) 

**Weight inflation:**

`totalWeightOfFragment` adds the Peras boost to the chain weight. Any fragment containing the attacker-chosen block gains `PerasWeight 15` on top of its block-count length, making it appear heavier than an honest chain of equal or slightly greater length: [5](#0-4) 

The default `perasWeight` is `PerasWeight 15`, meaning a single forged certificate can outweigh 15 honest blocks: [6](#0-5) 

---

### Impact Explanation

**High — Chain selection bug.** An unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions. By sending a `PerasCert` whose `pcCertBoostedBlock` points to a block on an adversarial fork, the attacker inflates that fork's weight by `PerasWeight 15`. If the adversarial fork is within `k` blocks of the honest tip, the node will switch to it. Because the certificate is accepted without any quorum, signature, or committee-membership check, the attacker needs no stake, no keys, and no special privileges — only a peer connection.

---

### Likelihood Explanation

Any peer reachable via the Peras object-diffusion mini-protocol can trigger this. The object-diffusion layer is a standard part of the node's network stack when Peras is enabled. No cryptographic material, stake, or operator access is required. The attacker only needs to construct a `PerasCert` CBOR value with a `pcCertBoostedBlock` pointing to a block already in the target node's VolatileDB.

---

### Recommendation

Replace the stub with a real implementation that, at minimum:

1. Verifies the certificate's aggregate vote signature against the committee's public keys for the relevant epoch.
2. Checks that the total stake weight of the signers exceeds the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. Verifies that the `pcCertRound` and `pcCertBoostedBlock` are consistent with the current epoch's parameters.

Until the full implementation is ready, the stub should be replaced with a hard `Left PerasValidationErr` (reject all) rather than a hard `Right` (accept all), so that enabling Peras does not open the chain-selection attack surface.

---

### Proof of Concept

1. Attacker connects to a target node as a Peras object-diffusion peer.
2. Attacker identifies block `B` in the node's VolatileDB that sits on an adversarial fork `F` (shorter than the honest chain by up to 14 blocks).
3. Attacker constructs and sends:
   ```
   PerasCert { pcCertRound = <any fresh round>, pcCertBoostedBlock = point(B) }
   ```
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally. [7](#0-6) 
5. The certificate is stored and `chainSelSync` triggers `chainSelectionForBlock` for `B`. [8](#0-7) 
6. `totalWeightOfFragment` now scores fork `F` as `length(F) + 15`, which exceeds the honest chain's score if the honest chain is at most 14 blocks longer. [9](#0-8) 
7. The node switches to fork `F`, diverging from the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L127-131)
```haskell
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
```
