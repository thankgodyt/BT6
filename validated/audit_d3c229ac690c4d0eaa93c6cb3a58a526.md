### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every inbound certificate, performing zero quorum, signature, or committee verification. The inbound certificate pipeline (`processCerts`) additionally hard-codes `mkPerasParams` instead of using ledger-derived parameters. Together, any unprivileged peer can inject an arbitrary `PerasCert` — with any round number and any boosted block point — into the local `PerasCertDB`, triggering chain selection for the boosted block and granting it unearned Peras weight.

---

### Finding Description

**Analog to the external report:** The external report describes a multisig where the quorum/confirmation check is broken — either too strict (exact equality) or retroactively invalidated by parameter changes — so that a previously confirmed transaction can no longer be executed. The analog here is the inverse but in the same vulnerability class: the Peras certificate quorum check is entirely absent, so an unconfirmed (fabricated) certificate is treated as fully confirmed.

**Root cause — stub validation:** [1](#0-0) 

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

This is the **only** implementation of `validatePerasCert` in the codebase (the universal `instance StandardHash blk => BlockSupportsPeras blk`). It accepts every certificate unconditionally.

**Root cause — hardcoded parameters in the inbound pipeline:**

Both production pool writers pass `mkPerasParams` (hardcoded defaults) rather than ledger-derived parameters: [2](#0-1) [3](#0-2) 

Even if `validatePerasCert` were later fixed, it would still use stale hardcoded params rather than the current ledger state — directly analogous to the external report's finding that the multisig uses the current (potentially changed) `required` value rather than the value at confirmation time.

**Inbound processing path:** [4](#0-3) 

`processCerts` filters out already-known round numbers, then calls `validateCert` on the remainder. Because `validateCert = validatePerasCert mkPerasParams` always returns `Right`, every new-round certificate from a peer is accepted and forwarded to `addCert`.

**Chain selection consequence:** [5](#0-4) 

`chainSelSync` processes the accepted certificate: it adds it to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block, granting it `perasWeight = 15` extra chain-selection weight.

**Missing rethrow policy entry:**

`PerasCertInboundException` (thrown when validation fails) is absent from `consensusRethrowPolicy`, while `PerasVoteDbError` is present: [6](#0-5) 

Since `validatePerasCert` never fails, this gap is currently unreachable, but it means that if validation were fixed, a peer sending an invalid certificate would trigger the default reconnect-after-delay policy rather than a permanent disconnect.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with:
- `pcCertRound` set to any round not yet in the local DB
- `pcCertBoostedBlock` pointing to any block the attacker wants to boost

The certificate is accepted without any quorum, signature, or committee check. The boosted block receives `perasWeight = 15` extra weight in chain selection. If the attacker's target block is on a minority fork, the honest node may switch to that fork, diverging from the canonical chain. This is a **chain selection manipulation** bug reachable by any peer connected via the object diffusion mini-protocol.

Impact classification: **High** — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The object diffusion mini-protocol for Peras certificates is active whenever Peras is enabled. Any connected peer can send a `PerasCert` message. No stake, keys, or special privileges are required. The attacker only needs to know a valid block hash to target. Likelihood is **High** once Peras is deployed on a network with this code.

---

### Recommendation

1. **Implement `validatePerasCert`** to verify the certificate's quorum proof (aggregate signature or vote set) against the current ledger's committee and stake distribution, as tracked in issue #120.
2. **Thread ledger-derived `PerasCfg`** through `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` instead of using the hardcoded `mkPerasParams`, so that validation always uses the parameters that were in effect at the certificate's round — directly addressing the analog to the external report's parameter-mismatch root cause.
3. **Add `PerasCertInboundException` to `consensusRethrowPolicy`** with `theyBuggyOrEvil` (permanent peer disconnect) so that once real validation is in place, peers sending invalid certificates are disconnected rather than reconnected after a delay.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect a malicious peer to an honest node via the object diffusion mini-protocol.
2. The malicious peer sends a `PerasCert` message containing:
   - `pcCertRound = N` (any round not yet in the honest node's `PerasCertDB`)
   - `pcCertBoostedBlock = <hash of a block on a minority fork>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is inserted into `PerasCertDB` with boost weight 15.
5. `chainSelSync` triggers `chainSelectionForBlock` for the minority-fork block.
6. The honest node's chain selection now weights the minority-fork block 15 units heavier, potentially switching to the attacker's preferred chain.

No cryptographic material, stake, or operator access is required.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/RethrowPolicy.hs (L101-108)
```haskell
    -- Peras components as part of the ChainDB can create exceptions, see
    -- https://github.com/tweag/cardano-peras/issues/216
    <> mkRethrowPolicy
      ( \_ctx (e :: PerasVoteDbError blk) ->
          case e of
            MultipleWinnersInRound{} -> ourBug -- TODO: should we instead shutdown the node?
            ForgingCertError{} -> ourBug
      )
```
