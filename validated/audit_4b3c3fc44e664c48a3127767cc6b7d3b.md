### Title
`validatePerasCert` Stub Unconditionally Accepts All Inbound Peras Certificates, Enabling Unauthorized Chain-Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or protocol-level checks. This stub is wired directly into the production node-to-node Peras certificate diffusion inbound handler. Any unprivileged peer can therefore inject arbitrary `PerasCert` objects — targeting any block, for any round — and have them accepted, stored in the `PerasCertDB`, and used to boost chain weight in `ChainSel`, without possessing any valid quorum of votes or cryptographic proof.

---

### Finding Description

**Root cause — stub validation always returns `Right`:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal instance for `BlockSupportsPeras` (the only instance in the codebase) implements `validatePerasCert` as:

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

No signature, quorum, round-number range, boosted-block existence, or any other check is performed. Every certificate is stamped `ValidatedPerasCert` with the full `perasWeight` boost from the hardcoded `mkPerasParams` (default `PerasWeight 15`). [2](#0-1) 

**Production inbound path — stub is wired into the live miniprotocol handler:**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` passes `validatePerasCert mkPerasParams` directly as the validation function for all inbound certificates:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

This writer is then registered as the live `hPerasCertDiffusionClient` handler in the production node-to-node network stack:

```haskell
(makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [4](#0-3) 

**`processCerts` trusts the stub's output:**

`processCerts` calls the supplied `validateCert` function and, if it returns `Right`, immediately timestamps and stores the certificate: [5](#0-4) 

**Chain selection acts on the injected certificate:**

`chainSelSync` in `ChainSel.hs` receives the stored certificate and triggers chain selection for the boosted block, using the attacker-supplied `pcCertBoostedBlock` point: [6](#0-5) 

**End-to-end exploit path:**

1. Attacker peer connects to an honest node via the node-to-node miniprotocol.
2. Attacker sends a crafted `PerasCert` via the Peras certificate diffusion protocol, with `pcCertBoostedBlock` pointing to a block on an adversarial fork.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })` unconditionally.
4. The certificate is stored in `PerasCertDB`.
5. `chainSelSync` triggers chain selection for the boosted block; the adversarial fork now has `+15` weight.
6. Repeating across multiple rounds (one certificate per round, since `PerasCertDB` deduplicates by round number) accumulates weight on the adversarial fork.
7. Once the adversarial fork's total weight exceeds the honest chain's weight, the node switches to the adversarial chain.

---

### Impact Explanation

**Critical — bypass of certificate verification enabling unauthorized chain-weight manipulation and potential consensus safety failure.**

The `validatePerasCert` stub removes the entire cryptographic gate that is supposed to prevent unauthorized Peras boosts. An unprivileged peer with a valid network connection can:

- Inject certificates for arbitrary rounds pointing to arbitrary blocks, with no quorum of votes and no cryptographic proof.
- Accumulate `PerasWeight 15` per injected round on any target block.
- Cause an honest node to prefer a non-canonical (adversarial) chain once the injected weight exceeds the honest chain's weight advantage.

This directly maps to the allowed impact category: **bypass of certificate verification that enables unauthorized certificate acceptance**, and **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The Peras certificate diffusion miniprotocol is wired into the production `NodeToNode` handler with no feature flag or version gate visible in the code. Any peer that successfully negotiates the protocol version can send `PerasCert` objects. The attack requires only a network connection and knowledge of a target block's `Point` — no keys, no stake, no privileged access.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:

1. The certificate's aggregate BLS signature over the claimed quorum of votes.
2. That the quorum of votes meets the `perasQuorumStakeThreshold` from the on-chain `PerasParams`.
3. That the `pcCertRound` is within the valid range (not too old, not in the future).
4. That the `pcCertBoostedBlock` exists and satisfies `perasBlockMinSlots`.

Until the real implementation is ready, the inbound certificate diffusion handler should be disabled or gated behind a feature flag so that no peer-supplied certificates are accepted.

Additionally, replace the hardcoded `mkPerasParams` with the actual on-chain `PerasParams` extracted from the ledger state, consistent with how other protocol parameters are consumed.

---

### Proof of Concept

```
1. Start an honest Cardano node with Peras certificate diffusion enabled.
2. Connect a malicious peer that speaks the node-to-node protocol.
3. Malicious peer sends a PerasCert message:
     PerasCert { pcCertRound = R, pcCertBoostedBlock = <point on adversarial fork> }
4. Observe: processCerts calls validatePerasCert, which returns Right unconditionally.
5. Observe: PerasCertDB stores the certificate for round R.
6. Observe: chainSelSync triggers chain selection; the adversarial fork gains PerasWeight 15.
7. Repeat for rounds R+1, R+2, ... to accumulate weight.
8. Once accumulated weight exceeds the honest chain's block-count advantage, the node
   switches to the adversarial chain — a consensus safety failure.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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
