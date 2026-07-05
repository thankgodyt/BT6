### Title
Peras Certificate Validation Completely Bypassed — Any Peer Can Inject Arbitrary Chain-Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The sole production implementation of `validatePerasCert` in the `BlockSupportsPeras` class unconditionally returns `Right` for every certificate it receives, performing no cryptographic, quorum, round-validity, or signature checks. Any unprivileged peer that can send a `PerasCert` message via the Peras ObjectDiffusion mini-protocol can inject an arbitrary certificate that the node will accept, store, and use to apply a chain-weight boost during chain selection.

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for certificate acceptance. The only instance in the codebase is a catch-all stub:

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

This stub is the **only** instance — there is no Cardano-specific override. The comment `-- TODO: degenerate instance for all blks to get things to compile` confirms it was never replaced with real validation. [2](#0-1) 

The production inbound path for peer-supplied certificates calls this stub directly:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
``` [3](#0-2) 

`processCerts` partitions results and only rejects a batch when `validateCert` returns `Left`. Because `validatePerasCert` never returns `Left`, every certificate from every peer is accepted unconditionally. [4](#0-3) 

Once accepted, the certificate is forwarded to `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` then applies the certificate's weight boost (`perasWeight = 15` by default) to the boosted block during chain selection: [5](#0-4) 

The weight boost is defined as `PerasWeight 15` in `mkPerasParams`, meaning a single injected certificate adds 15 weight units to an arbitrary block, potentially making a shorter (by block count) adversarial chain preferred over the honest chain. [6](#0-5) 

The `SecurityParam` for Peras is interpreted as a maximum rollback **weight**, not just block count: [7](#0-6) 

### Impact Explanation

An unprivileged peer sends a crafted `PerasCert{pcCertRound = r, pcCertBoostedBlock = p}` targeting any block `p` in the VolatileDB. The node accepts it without any quorum, signature, or round-validity check, stores it, and applies a weight boost of 15 to block `p`. This can cause the node to prefer a non-canonical chain that contains `p` over the honest chain, constituting a chain-selection manipulation. Because the weight boost counts against the `maxRollbackWeight` (`k`), a sequence of injected certificates can exhaust the rollback budget and permanently lock the node onto an adversarial chain.

**Impact: High** — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

### Likelihood Explanation

The Peras ObjectDiffusion mini-protocol is wired into the production `NodeKernel`. Any peer that establishes a connection and speaks the Peras certificate diffusion sub-protocol can send arbitrary `PerasCert` messages. No stake, key material, or special privilege is required. The attack is trivially reproducible on a private testnet with two nodes.

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that checks:
1. The certificate's aggregate BLS signature over the claimed voter set.
2. That the voter set's total stake meets the `perasQuorumStakeThreshold`.
3. That each voter's eligibility proof (VRF output) is valid for the claimed round.
4. That `pcCertRound` falls within the acceptable window relative to the current chain tip.

Until real validation is implemented, the Peras certificate ObjectDiffusion mini-protocol should not be enabled on nodes connected to untrusted peers.

### Proof of Concept

On a private two-node testnet with Peras ObjectDiffusion enabled:

1. Attacker node connects to the victim node.
2. Attacker sends a `PerasCert` message with `pcCertRound = currentRound` and `pcCertBoostedBlock = <hash of a block on an adversarial fork>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = 15}` unconditionally.
4. `addPerasCertAsync` enqueues the cert; `chainSelSync` applies the 15-unit weight boost to the adversarial block.
5. If the adversarial chain's weighted length now exceeds the honest chain's weighted length, the victim node switches to the adversarial fork.
6. Repeating with multiple certificates for blocks on the adversarial chain can exhaust the rollback weight budget, permanently preventing the node from returning to the honest chain. [1](#0-0) [3](#0-2) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-38)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
```
