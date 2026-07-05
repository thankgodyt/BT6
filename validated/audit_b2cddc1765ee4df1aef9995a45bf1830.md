### Title
Peras Certificate Validation Bypass Lets Any Peer Inject Arbitrary Chain-Weight Boosts — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance used for all block types contains a stub `validatePerasCert` that unconditionally returns `Right` — accepting every inbound certificate without performing any cryptographic or semantic check. Because the ObjectDiffusion mini-protocol feeds peer-supplied certificates directly through this function and into `ChainDB`, any unprivileged peer can inject crafted `PerasCert` objects that assign the full Peras weight boost to an arbitrary block in the VolatileDB, directly influencing chain selection.

### Finding Description

**Root cause — always-`Right` certificate validation**

The degenerate `BlockSupportsPeras` instance (annotated "TODO: degenerate instance for all blks to get things to compile") is the only instance in scope for all block types:

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

No signature, quorum, committee-membership, round-number, or boosted-block-existence check is performed. Every certificate, regardless of content, is stamped `ValidatedPerasCert` with the full `perasWeight params` boost.

**Inbound path — peer → `processCerts` → `ChainDB`**

`makePerasCertPoolWriterFromChainDB` wires the production writer:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- always Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
```

`processCerts` calls `validateCert` on each certificate not already in the DB. Because `validatePerasCert` always returns `Right`, every crafted certificate passes and is forwarded to `ChainDB.addPerasCertAsync`.

**Chain-selection side-effect — `chainSelSync`**

`chainSelSync` processes the accepted certificate:

1. Checks that `pointSlot boostedBlock >= AF.anchorToSlotNo immTip` (only age-gated, not authenticity-gated).
2. Looks up the boosted block header in the VolatileDB.
3. If found, calls `chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment`, which re-runs chain selection with the Peras weight snapshot that now includes the injected boost.

`chainSelection` sorts candidates using `compareChainDiffs bcfg weights curChain`, where `weights` is the `PerasWeightSnapshot` populated from the `PerasCertDB`. A crafted certificate boosting a fork block therefore adds `perasWeight params` to that fork's effective chain weight, potentially making it preferred over the honest chain.

**End-to-end exploit path**

1. Attacker (any peer reachable via the ObjectDiffusion mini-protocol) constructs a `PerasCert` with `pcCertBoostedBlock` pointing to a fork block already present in the target node's VolatileDB (e.g., a block the attacker produced with minimal stake, or any stale fork block the node received earlier).
2. Attacker sends the crafted certificate batch to the target node.
3. `processCerts` calls `validatePerasCert mkPerasParams` → always `Right`.
4. Certificate is stored in `PerasCertDB`; `getWeightSnapshot` now reflects the injected boost.
5. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `chainSelection` re-evaluates candidates; the fork block's chain now carries the full Peras weight boost.
7. If the boosted fork is otherwise competitive (e.g., same length as the honest tip), the node switches to the fork.

### Impact Explanation

An unprivileged peer can make an honest node prefer a non-canonical chain by injecting crafted Peras certificates. This is a **High** chain-selection integrity failure: the Peras weight mechanism is designed to make the honest chain *harder* to displace; bypassing certificate validation inverts this guarantee, allowing an adversary to weaponize the weight boost against the honest chain. In the worst case, a node can be made to roll back to a fork and adopt an attacker-controlled chain tip, violating the Common Prefix property for that node.

### Likelihood Explanation

The ObjectDiffusion mini-protocol is a standard node-to-node protocol; any peer that can establish a connection can send certificate batches. No stake, keys, or privileged access are required to craft a `PerasCert` — the type has no cryptographic fields in the degenerate instance (only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`). The only precondition is that the target block exists in the node's VolatileDB, which is achievable by any peer that can influence which blocks the node downloads, or by targeting stale fork blocks already present.

### Recommendation

Replace the stub with a real implementation that verifies:
- The aggregate BLS signature over the claimed voter set against the committee's public keys.
- That the voter set constitutes a quorum (total stake above the Peras threshold).
- That `pcCertRound` falls within the expected round window.
- That `pcCertBoostedBlock` matches the election candidate the votes were cast for.

Until the real implementation is ready, the degenerate instance should at minimum reject all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all, so that the ObjectDiffusion path cannot be used to inject weight boosts.

### Proof of Concept

```
Attacker node A connects to honest node H via the ObjectDiffusion mini-protocol.

1. A observes that H's VolatileDB contains a fork block F at slot S
   (e.g., a competing block produced by A with minimal stake, or any
   stale fork block H received during normal operation).

2. A constructs:
     cert = PerasCert
       { pcCertRound      = currentRound
       , pcCertBoostedBlock = BlockPoint S (hash of F)
       }

3. A sends [cert] to H via the ObjectDiffusion cert diffusion channel.

4. H's processCerts calls validatePerasCert mkPerasParams cert
   → always returns Right (ValidatedPerasCert { vpcCert = cert,
                                                vpcCertBoost = perasWeight mkPerasParams })

5. H stores the ValidatedPerasCert in PerasCertDB.
   getWeightSnapshot now returns a snapshot with perasWeight applied to F.

6. chainSelSync triggers chainSelectionForBlock for F.
   compareChainDiffs now ranks F's chain higher by perasWeight.

7. If F's chain length >= H's current chain length, H switches to F,
   rolling back to the fork point and adopting A's chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1144)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
 where
  ChainSelEnv{..} = chainSelEnv

  sortCandidates ::
    [(ChainDiff (Header blk), ReasonForSwitch' blk)] -> [(ChainDiff (Header blk), ReasonForSwitch' blk)]
  sortCandidates = sortBy ((flip $ compareChainDiffs bcfg weights curChain) `on` fst)
```
