### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Selection Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` stub — no cryptographic signature, no committee-membership check, no round-validity check is performed. Because the inbound certificate pipeline in `processCerts` delegates all trust decisions to this function, any unprivileged peer can inject an arbitrary `PerasCert` that passes "validation" and is stored in the `PerasCertDB`. The stored certificate then triggers chain selection and applies a configurable weight boost (`perasWeight = 15`) to the boosted block, potentially causing the node to prefer a non-canonical fork.

### Finding Description

**Root cause — stub validation that always succeeds**

The `BlockSupportsPeras` class declares `validatePerasCert` as the cryptographic gate for inbound certificates. The only instance in the codebase is a universal degenerate instance that unconditionally returns `Right`:

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

This instance is declared as `instance StandardHash blk => BlockSupportsPeras blk`, making it the universal instance for all block types including production Cardano blocks. [2](#0-1) 

**Inbound pipeline trusts the stub**

`processCerts` in the object-diffusion layer is the entry point for peer-supplied certificates. It calls `validatePerasCert mkPerasParams` as its sole validation step before accepting a certificate:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate from every peer passes this check. The certificate is then timestamped and forwarded to `ChainDB.addPerasCertAsync`.

**Chain selection is triggered with the injected weight**

`chainSelSync` processes the accepted certificate: it stores it in `PerasCertDB`, then calls `chainSelectionForBlock` for the boosted block. The certificate carries `vpcCertBoost = perasWeight params = 15`, which is applied as a weight advantage in chain selection: [4](#0-3) 

The `perasWeight` is set to 15 in `mkPerasParams`: [5](#0-4) 

**Exploit path**

1. Attacker connects to a victim node as a normal peer via the object-diffusion miniprotocol for Peras certificates.
2. Attacker crafts a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of a block on an adversarial fork already in the victim's VolatileDB>`.
3. Attacker sends the certificate. `processCerts` calls `validatePerasCert mkPerasParams` → always `Right`.
4. The certificate is stored in `PerasCertDB` with `vpcCertBoost = 15`.
5. `chainSelSync` calls `chainSelectionForBlock` for the boosted block.
6. Chain selection now compares the adversarial fork (with +15 weight) against the current chain. If the adversarial fork is within 15 blocks of the current tip, the node switches to it.

### Impact Explanation

An unprivileged peer can force an honest node to switch to a non-canonical fork by injecting a certificate that grants 15 blocks of artificial weight to any block already present in the node's VolatileDB. This is a **High** severity chain-selection bug: it lets an attacker make an honest node prefer a less-secure or adversarially-controlled chain beyond the intended security assumptions of the Ouroboros protocol, without requiring any stake, keys, or privileged access.

### Likelihood Explanation

The attack requires only a standard peer connection and knowledge of a block hash present in the victim's VolatileDB (obtainable via ChainSync). No cryptographic material, stake, or operator access is needed. The object-diffusion miniprotocol for Peras certificates is wired into the production diffusion layer via `makePerasCertPoolWriterFromChainDB`. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase and applies universally.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real cryptographic check that verifies:
- The certificate's committee-membership proof (that the signers were legitimately elected for the given round).
- The aggregate signature over the certificate content.
- That the round number is within the valid window relative to the current chain tip.

Until real validation is implemented, the inbound certificate pipeline should reject all externally-supplied certificates (e.g., return `Left PerasValidationErr` unconditionally) rather than accept them all. The TODO at `https://github.com/tweag/cardano-peras/issues/120` tracks this work and should be treated as a security-critical blocker before the Peras diffusion path is enabled on any network where adversarial peers are possible.

### Proof of Concept

1. Connect to a victim node as a peer via the Peras certificate object-diffusion miniprotocol.
2. Observe (via ChainSync) a block hash `H` on a fork that is at most 15 blocks shorter than the victim's current chain tip and is present in the victim's VolatileDB.
3. Send a `PerasCert { pcCertRound = R, pcCertBoostedBlock = H }` for any round `R` not already in the victim's `PerasCertDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
5. `chainSelSync` stores the cert and calls `chainSelectionForBlock` for block `H`.
6. Chain selection computes the weight of the fork containing `H` as `(fork block count) + 15` vs. the current chain's block count. If `(fork block count) + 15 > current chain block count`, the node switches to the adversarial fork.
7. The victim node has been made to prefer a non-canonical chain without any cryptographic proof of committee membership or quorum.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
