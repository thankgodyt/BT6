### Title
Missing Peras Certificate Cryptographic Validation Unconditionally Accepts Any Peer-Supplied Certificate - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` catch-all instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate, bypassing all cryptographic and structural checks. This is the instance wired into the live Peras certificate inbound diffusion path. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted block, have it accepted without verification, and trigger chain selection for that block.

---

### Finding Description

**Root cause — always-`Right` stub validation:** [1](#0-0) 

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

This is the **catch-all instance** declared for `StandardHash blk => BlockSupportsPeras blk`: [2](#0-1) 

No more-specific instance with real validation exists in the repository. The stub is therefore the live instance used in production diffusion paths.

**How the stub is wired into the inbound diffusion path:**

`processCerts` is the function that handles every batch of inbound Peras certificates received from a peer: [3](#0-2) 

It is called from both pool-writer constructors with `validatePerasCert mkPerasParams` as the validation callback: [4](#0-3) [5](#0-4) 

Because `validatePerasCert` always returns `Right`, the `partitionEithers` call inside `processCerts` always produces an empty error list, and every certificate in the batch is unconditionally forwarded to `addCert`.

**Downstream chain-selection effect:**

Once a certificate is stored in `PerasCertDB`, `chainSelSync` is triggered for the boosted block: [6](#0-5) 

This causes the node to re-evaluate chain selection with the injected certificate's weight boost applied to the attacker-chosen block.

**Analog to the external report:**

The external report identified a missing `require(!isFactory[_pairFactory])` guard in `addFactory()` — a check that should have rejected already-registered factories was simply absent, allowing invariant-breaking duplicates. Here, the analogous guard is the entire body of `validatePerasCert`: the check that should reject certificates with invalid committee signatures, wrong round numbers, or forged boosted-block pointers is absent (replaced by an unconditional `Right`), allowing invariant-breaking acceptance of any peer-supplied certificate.

---

### Impact Explanation

**Bypass of Peras certificate verification checks enabling unauthorized certificate acceptance.**

An unprivileged peer can craft a `PerasCert` with any `pcCertRound` and any `pcCertBoostedBlock` (including a block on a minority or adversarial fork). The certificate passes `validatePerasCert`, is stored in `PerasCertDB`, and causes `chainSelSync` to run chain selection with the injected boost weight. If the boosted block is on a competing fork, the node may switch to that fork, constituting a chain-selection manipulation by an unprivileged network peer.

This falls under the **Critical** allowed impact: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

Any peer that can establish a connection and speak the Peras certificate object-diffusion mini-protocol can trigger this. No stake, no keys, no operator access, and no brute force are required. The attack is deterministic and reproducible on a private testnet with a single malicious peer.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that verifies:

1. The certificate's committee aggregate signature over `(roundNo, boostedBlock)`.
2. That the signing committee members were eligible for the claimed round (VRF/sortition check).
3. That the quorum threshold is met by the verified signers' combined stake.

Until real validation is in place, the inbound diffusion path for Peras certificates should not be enabled on any node that participates in consensus.

---

### Proof of Concept

```
Private testnet sequence:
1. Start a node with Peras object diffusion enabled.
2. Connect a malicious peer that speaks the Peras cert diffusion mini-protocol.
3. Peer sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <adversarial fork tip> }.
4. processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
5. addCert stores the certificate in PerasCertDB.
6. chainSelSync fires for the adversarial fork tip.
7. Chain selection re-runs with the injected boost weight; if the adversarial fork
   is otherwise competitive, the node switches to it.
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
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
